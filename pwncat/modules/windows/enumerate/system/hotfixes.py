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


class HotfixData(Fact):
    def __init__(
        self, source, caption: str, hotfixid: str, tag: str, installed_on: str
    ):
        super().__init__(source=source, types=["system.hotfixes"])

        self.hotfixid: str = hotfixid

        self.tag: str = tag

        self.caption: str = caption

        self.installed_on: str = installed_on

    def title(self, session):
        return f"[cyan]{rich.markup.escape(self.hotfixid)}[/cyan] {rich.markup.escape(self.tag)} installed on [blue]{rich.markup.escape(self.installed_on)}[/blue] ([blue]{rich.markup.escape(self.caption)}[/blue])"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.hotfixes"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic",
                "qfe",
                "get",
                "Caption,HotFixID,Description,InstalledOn",
                "/format:csv",
            ],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command
        with proc.stdout as stream:
            for line in stream:
                line = line.strip()

                if not line or "Caption,Description,HotFixID,InstalledOn" in line:
                    continue

                _, caption, tag, hotfixid, installed_on = line.split(",")
                yield HotfixData(self.name, caption, hotfixid, tag, installed_on)

        proc.wait()
