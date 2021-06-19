#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class PowerShellHistory(Fact):
    def __init__(self, source, path: str):
        super().__init__(source=source, types=["powershell.history"])

        self.path: str = path

    def title(self, session):
        if self.path:
            return f"PowerShell history file: '{rich.markup.escape(self.path)}'"
        else:
            return f"[yellow]PowerShell history file not found[/yellow]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["powershell.history"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                "(Get-PSReadLineOption | select -ExpandProperty HistorySavePath)"
            )

            if not result:
                return PowerShellHistory(self.name, "")

            if isinstance(result[0], list) and result:
                path = "\n".join(result[0])
            else:
                path = result[0]

        except PowershellError as exc:
            raise ModuleFailed("failed to retrieve powershell history file") from exc

        yield PowerShellHistory(self.name, path)
