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


"""
TODO: This should use csvreader.
"""

class ServicesData(Fact):
    def __init__(
        self,
        source,
        name: str,
        pid: int,
        start_mode: str,
        status: str,
    ):
        super().__init__(source=source, types=["system.services"])

        self.name: str = name

        self.pid: int = pid

        self.start_mode: str = start_mode

        self.status: str = status

    def title(self, session):
        out = f"[cyan]{rich.markup.escape(self.name)}[/cyan] (PID [blue]{self.pid}[/blue]) currently "
        if self.status == "Running":
            out += f"[bold green]{self.status}[/bold green] "
        else:
            out += f"[red]{self.status}[/red] "
        if self.start_mode == "Auto":
            out += f"([bold yellow]{self.start_mode}[/bold yellow] start)"
        else:
            out += f"([magenta]{self.start_mode}[/magenta] start)"
        return out
        


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.services"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            ["wmic.exe", "service", "get", "Caption,ProcessId,State,StartMode", "/format:csv"],
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
                    or 'Node,Caption,ProcessId,StartMode,State'
                    in line
                ):
                    continue

                _, name, pid, start_mode, status = (x.strip('"') for x in line.split(','))

                pid = int(pid)

                yield ServicesData(
                    self.name, name, pid, start_mode, status
                )

        proc.wait()
