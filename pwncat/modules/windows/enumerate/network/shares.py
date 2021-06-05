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


class NetworkShare(Fact):
    def __init__(self, source, name: str, caption: str, tag: str, install_date: str, path:str, status:str, share_type:str):
        super().__init__(source=source, types=["network.shares"])

        self.name: str = name
        self.install_date: str = install_date
        self.tag: str = tag
        self.share_type: str = share_type
        self.path: str = path
        self.status: str = status
        self.caption: str = caption

    def title(self, session):
        out = f"[dim][cyan]{rich.markup.escape(self.name)}[/cyan] {rich.markup.escape(self.tag)}"
        if self.path:
            out += f" at [blue]{rich.markup.escape(self.path)} [/blue][/dim]"
        else:
            out += "[/dim]"
        if self.tag.lower() not in ["remote admin", "default share", "remote ipc"]:
            out = out.replace('[dim]','[bold]').replace('[/dim]','[/bold]').replace('[cyan]', '[green]').replace('[/cyan]', '[/green]')
        return out



class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["network.shares"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        proc = session.platform.Popen(
            [
                "wmic.exe",
                "share",
                "get",
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

                if not line or "Node,AccessMask,AllowMaximum,Caption,Description,InstallDate,MaximumAllowed,Name,Path,Status,Type" in line:
                    continue

                _, access_mask, allow_maximum, caption, tag, install_date, maximum_allowed, name, path, status, share_type = line.split(",")
                yield NetworkShare(self.name, caption = caption, tag = tag, install_date = install_date, name = name, path = path, status = status, share_type = share_type)

        proc.wait()
