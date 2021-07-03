#!/usr/bin/env python3


import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class ClipboardData(Fact):
    def __init__(self, source, contents: str):
        super().__init__(source=source, types=["system.clipboard"])

        self.contents: bool = contents

    def title(self, session):
        return "Current clipboard contents:"

    def description(self, session):
        return f"[yellow]{rich.markup.escape(self.contents)}[/yellow]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.clipboard"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell("Get-Clipboard")

            if not result:
                return

            if isinstance(result[0], list) and result:
                contents = "\n".join(result[0])
            else:
                contents = result[0]

        except PowershellError as exc:
            raise ModuleFailed("failed to retrieve clipboard contents") from exc

        yield ClipboardData(self.name, contents)
