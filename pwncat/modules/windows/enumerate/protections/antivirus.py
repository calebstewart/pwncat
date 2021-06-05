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


class MountedDrive(Fact):
    def __init__(self, source, av_name: str, exe_path: str):
        super().__init__(source=source, types=["protection.antivirus"])

        self.av_name: str = av_name
        self.exe_path: str = exe_path

    def title(self, session):
        return f"Antivirus [red]{rich.markup.escape(self.av_name)}[/red] running from [yellow]{rich.markup.escape(self.exe_path)}[/yellow]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["protection.antivirus"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic.exe",
                "/Node:localhost",
                "/Namespace:\\\\root\\SecurityCenter2",
                "Path",
                "AntiVirusProduct",
                "Get",
                "displayName,pathToSignedReportingExe",
                "/Format:csv",
            ],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command
        with proc.stdout as stream:
            for line in stream:
                line = line.strip()

                if not line or "displayName,pathToSignedReportingExe" in line:
                    continue

                _, av_name, exe_path = line.split(",")
                yield MountedDrive(self.name, av_name, exe_path)

        proc.wait()
