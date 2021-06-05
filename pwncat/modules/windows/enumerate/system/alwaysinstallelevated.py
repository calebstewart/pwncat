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


class AlwaysInstallElevatedData(Fact):
    def __init__(self, source, enabled:bool, context: str):
        super().__init__(source=source, types=["system.alwaysinstallelevated"])

        self.enabled: bool = enabled
        self.context: str = context


    def title(self, session):
        out = "AlwaysInstallElevated is " + "[bold green]enabled[/bold green]" if self.enabled else "[red]disabled[/red]" 
        out += f" for this {self.context}"
        return out


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.alwaysinstallelevated"]
    PLATFORM = [Windows]

    def enumerate(self, session):


        registry_value = "AlwaysInstallElevated"
        registry_keys = [
            "HKCU:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\",
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\"
        ]


        for registry_key in registry_keys:
            try:
                result = session.platform.powershell(
                    f"Get-ItemPropertyValue {registry_key} -Name {registry_value}"
                )

                if not result:
                    raise ModuleFailed(
                        f"failed to retrieve registry value {registry_value}"
                    )

                status = bool(result[0])

            except PowershellError as exc:
                if "does not exist" in exc.errors[0]["Message"]:
                    status = bool(0) # default
                else:
                    raise ModuleFailed(
                        f"could not retrieve registry value {registry_value}: {exc}"
                    ) from exc

            if registry_key.startswith('HKCU'):
                yield AlwaysInstallElevatedData(self.name, status, "current user")
            else:
                yield AlwaysInstallElevatedData(self.name, status, "local machine")
