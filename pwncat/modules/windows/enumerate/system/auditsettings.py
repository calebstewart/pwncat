#!/usr/bin/env python3

import datetime
from typing import Any

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class AuditSettings(Fact):
    def __init__(self, source, setting: str, value: Any):
        super().__init__(source=source, types=["system.auditsettings"])

        self.setting = setting
        self.value = value

    def title(self, session):
        return f"[yellow]Audit [bold]{rich.markup.escape(self.setting)}[/bold][/yellow] = {rich.markup.escape(str(self.value))}"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.auditsettings"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"
            )

            if not result:
                return

            if isinstance(result[0], list) and result:
                settings = result[0]
            else:
                settings = result[0]

            for setting, value in settings.items():
                # Skip default/boilerplate values
                if setting not in (
                    "PSPath",
                    "PSParentPath",
                    "PSChildName",
                    "PSProvider",
                    "PSDrive",
                ):
                    yield AuditSettings(self.name, setting, value)

        except PowershellError as exc:
            raise ModuleFailed("failed to retrieve audit settings") from exc
