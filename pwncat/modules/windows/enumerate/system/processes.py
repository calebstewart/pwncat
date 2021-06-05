#!/usr/bin/env python3

from typing import Any, Dict, List

import pwncat
import rich.markup
from pwncat import util
from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.modules.enumerate import EnumerateModule, Schedule
from pwncat.platform import PlatformError
from pwncat.platform.windows import PowershellError, Windows


class ProcessData(Fact):
    def __init__(
        self,
        source,
        process_name: str,
        pid: int,
        session_name: str,
        status: str,
        user_name: str,
    ):
        super().__init__(source=source, types=["system.processes"])

        self.process_name: str = process_name

        self.pid: int = pid

        self.session_name: str = session_name

        self.status: str = status

        self.user_name: str = user_name

    def title(self, session):
        out = f"[cyan]{rich.markup.escape(self.process_name)}[/cyan] (PID [blue]{self.pid}[/blue]) status [yellow]{rich.markup.escape(self.status)}[/yellow] as user [magenta]{self.user_name}[/magenta]"
        if "NT AUTHORITY\\SYSTEM" in self.user_name:
            out = out.replace("[magenta]", "[red]").replace("[/magenta]", "[/red]")
        if self.status == "Running":
            out = out.replace("[yellow]", "[green]").replace("[/yellow]", "[/green]")
        return out


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.processes"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            ["tasklist", "/V", "/FO", "CSV"],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command
        with proc.stdout as stream:
            for line in stream:
                line = line.strip()

                if (
                    not line
                    or '"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"'
                    in line
                ):
                    continue

                (
                    process_name,
                    pid,
                    session_name,
                    _,
                    _,
                    status,
                    user_name,
                    _,
                    _,
                ) = (x.strip('"') for x in line.split('",'))

                pid = int(pid)

                yield ProcessData(
                    self.name, process_name, pid, session_name, status, user_name
                )

        proc.wait()
