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

class MountedDrive(Fact):
    def __init__(
        self, source, drive_letter: str, tag: str, drive_name: str, system_name: str
    ):
        super().__init__(source=source, types=["system.drives"])

        self.drive_letter: str = drive_letter
        self.tag: str = tag
        self.drive_name: str = drive_name
        self.system_name: str = system_name

    def title(self, session):
        return f"{rich.markup.escape(self.drive_letter)}:\\ '{rich.markup.escape(self.drive_name)}' mounted from [cyan]{rich.markup.escape(self.system_name)}[/cyan] ([blue]{rich.markup.escape(self.tag)}[/blue])"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.drives"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic",
                "logicaldisk",
                "get",
                "caption,description,volumename,systemname",
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

                if not line or "Caption,Description,SystemName,VolumeName" in line:
                    continue

                _, drive_letter, tag, system_name, drive_name = line.split(",")
                yield MountedDrive(
                    self.name, drive_letter[0], tag, drive_name, system_name
                )

        proc.wait()
