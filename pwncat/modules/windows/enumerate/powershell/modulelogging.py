#!/usr/bin/env python3

from typing import Dict

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class PowerShellModuleLogging(Fact):
    def __init__(self, source, registry_values: Dict):
        super().__init__(source=source, types=["powershell.modulelogging"])

        self.registry_values: bool = registry_values
        """ The current setting for PowerShell transcription"""

    def __getitem__(self, name):

        return self.registry_values[name]

    def title(self, session):
        if not self.registry_values["EnableModuleLogging"]:
            return "[green]PowerShell Module Logging is [bold]disabled[/bold][/green]"

        return "[red]PowerShell Module Logging is [bold]enabled[/bold][/red]"


class Module(EnumerateModule):
    """Enumerate the current PowerShell module logging settings on the target"""

    PROVIDES = ["powershell.modulelogging"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        registry_key = (
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"
        )

        registry_values = {
            "EnableModuleLogging": bool,
        }

        for registry_value, registry_type in registry_values.items():
            try:
                result = session.platform.powershell(
                    f"Get-ItemPropertyValue '{registry_key}' -Name '{registry_value}'"
                )

                if not result:
                    raise ModuleFailed(
                        f"failed to retrieve registry value {registry_value}"
                    )

                registry_values[registry_value] = registry_type(result[0])

            except PowershellError as exc:
                if "does not exist" in exc.message:
                    registry_values[registry_value] = registry_type(0)
                else:
                    raise ModuleFailed(
                        f"could not retrieve registry value {registry_value}: {exc}"
                    ) from exc

        yield PowerShellModuleLogging(self.name, registry_values)
