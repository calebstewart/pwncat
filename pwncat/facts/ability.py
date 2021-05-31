#!/usr/bin/env python3
import shlex
import functools
import subprocess
from io import TextIOWrapper
from typing import IO, Any, Callable

import pwncat.subprocess
from pwncat.db import Fact
from pwncat.gtfobins import Stream, Capability
from pwncat.platform.linux import LinuxReader, LinuxWriter


def build_gtfo_ability(
    source: str,
    uid: Any,
    method: "pwncat.gtfobins.MethodWrapper",
    source_uid=None,
    **kwargs,
):
    """ Build a escalation ability from a GTFOBins method """

    if method.cap == Capability.READ:
        return GTFOFileRead(
            source=source, source_uid=source_uid, uid=uid, method=method, **kwargs
        )
    if method.cap == Capability.WRITE:
        return GTFOFileWrite(
            source=source,
            uid=uid,
            method=method,
            length=100000000000,  # TODO: WE SHOULD FIX THIS???
            source_uid=source_uid,
            **kwargs,
        )
    if method.cap == Capability.SHELL:
        return GTFOExecute(
            source=source, source_uid=source_uid, uid=uid, method=method, **kwargs
        )


class FileReadAbility(Fact):
    """Ability to read a file as a different user"""

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["ability.file.read"], source=source)

        self.uid = uid
        self.source_uid = source_uid

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ) -> IO:
        """Open a file for reading. This method mimics the builtin open
        function, and returns a file-like object for reading."""


class FileWriteAbility(Fact):
    """Ability to write a file as a different user"""

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["ability.file.write"], source=source)

        self.uid = uid
        self.source_uid = source_uid

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ) -> IO:
        """Open a file for writing. This method mimics the builtin open
        function and returns a file-like object for writing."""


class ExecuteAbility(Fact):
    """Ability to execute a binary as a different user"""

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["ability.execute"], source=source)

        self.source_uid = source_uid
        self.uid = uid

    def shell(
        self, session: "pwncat.manager.Session"
    ) -> Callable[["pwncat.manager.Session"], None]:
        """Replace the current shell with a new shell as the identified user

        :param session: the session to operate on
        :type session: pwncat.manager.Session
        :returns: Callable - A lambda taking the session and exiting the new shell
        """


class SpawnAbility(Fact):
    """Ability to spawn a new process as a different user without communications"""

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["ability.spawn"], source=source)

        self.source_uid = source_uid
        self.uid = uid

    def execute(self, session: "pwncat.manager.Session", command: str):
        """Utilize this ability to execute a command as a different user

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :param command: a command to execute
        :type command: str
        """


class GTFOFileRead(FileReadAbility):
    """Utilize a GTFO Method Wrapper to implement the FileReadAbility"""

    def __init__(self, source, source_uid, uid, method, **kwargs):
        super().__init__(source=source, source_uid=source_uid, uid=uid)

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
        source_user = session.find_user(uid=self.source_uid)

        if source_user == None:
            source_user = "[green]ANY[green]"
        else:
            source_user = f"[blue]{source_user.name}[/blue]"

        if "suid" in self.kwargs:
            description = " ([red]SUID[/red])"
        elif "spec" in self.kwargs:
            description = " ([red]SUDO[/red])"
        else:
            description = ""

        return f"file read as [blue]{user.name}[/blue] via [cyan]{self.method.binary_path}[/cyan]{description} from {source_user} ([magenta]{self.source}[/magenta])"


class GTFOFileWrite(FileWriteAbility):
    """Utilize a GTFO Method Wrapper to implement the FileWriteAbility"""

    def __init__(self, source, source_uid, uid, method, **kwargs):
        super().__init__(source=source, source_uid=source_uid, uid=uid)

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
        source_user = session.find_user(uid=self.source_uid)

        if source_user == None:
            source_user = "[green]ANY[green]"
        else:
            source_user = f"[blue]{source_user.name}[/blue]"

        if "suid" in self.kwargs:
            description = " ([red]SUID[/red])"
        elif "spec" in self.kwargs:
            description = " ([red]SUDO[/red])"
        else:
            description = ""

        return f"file write as [blue]{user.name}[/blue] via [cyan]{self.method.binary_path}[/cyan]{description} from {source_user} ([magenta]{self.source}[/magenta])"


class GTFOExecute(ExecuteAbility):
    """Execute a remote binary with a given GTFObins capability"""

    def __init__(self, source, source_uid, uid, method, **kwargs):
        super().__init__(source=source, source_uid=source_uid, uid=uid)

        self.method = method
        self.kwargs = kwargs

    def send_command(self, session, command: bytes = None):
        """Send the command to the target for this GTFObin"""

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

        # Figure out what shell to use based on the environment
        shell = session.platform.getenv("SHELL")
        if shell is None:
            shell = "/bin/sh"

        full_command = shell

        # Construct the GTFObins payload
        payload, input_data, exit_cmd = self.method.build(
            gtfo=session.platform.gtfo, shell=full_command, **self.kwargs
        )

        # Send the payload
        session.platform.channel.send(payload.encode("utf-8") + b"\n")

        # Send the input needed to trigger execution
        session.platform.channel.send(input_data)

        return lambda session: session.platform.channel.send(
            exit_cmd.encode("utf-8") + b"\n"
        )

    def title(self, session):
        user = session.find_user(uid=self.uid)
        source_user = session.find_user(uid=self.source_uid)

        if source_user == None:
            source_user = "[green]ANY[green]"
        else:
            source_user = f"[blue]{source_user.name}[/blue]"

        if "suid" in self.kwargs:
            description = " ([red]SUID[/red])"
        elif "spec" in self.kwargs:
            description = " ([red]SUDO[/red])"
        else:
            description = ""

        return f"shell as [blue]{user.name}[/blue] via [cyan]{self.method.binary_path}[/cyan]{description} from {source_user} ([magenta]{self.source}[/magenta])"
