#!/usr/bin/env python3

from typing import Dict

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class PowerShellTranscription(Fact):
    def __init__(self, source, registry_values: Dict):
        super().__init__(source=source, types=["powershell.transcription"])

        self.registry_values: bool = registry_values
        """ The current setting for PowerShell transcription"""

    def __getitem__(self, name):

        return self.registry_values[name]

    def title(self, session):
        if not self.registry_values["EnableTranscripting"]:
            return "[green]PowerShell Transcription Logging is [bold]disabled[/bold][/green]"

        return "[red]PowerShell Transcription Logging is [bold]enabled[/bold][/red]"

    def description(self, session):
        if not self.registry_values["EnableTranscripting"]:
            return None

        output = []
        for registry_name in self.registry_values.keys():
            registry_value = self.registry_values[registry_name]
            # Ingore the big LAPS property we have already displayed
            if registry_name == "EnableTranscripting":
                continue

            if registry_name == "OutputDirectory":
                if registry_value == "0":
                    output.append(
                        f"[cyan]{rich.markup.escape(registry_name)}[/cyan] not defined, likely $env:\\USERPROFILE"
                    )
                else:
                    output.append(
                        f"[cyan]{rich.markup.escape(registry_name)}[/cyan] = '{rich.markup.escape(registry_value)}'"
                    )

            if isinstance(registry_value, bool):
                if registry_value == True:
                    output.append(
                        f"[cyan]{rich.markup.escape(registry_name)}[/cyan] is [bold red]enabled[/bold red]"
                    )
                else:
                    output.append(
                        f"[cyan]{rich.markup.escape(registry_name)}[/cyan] is [bold green]disabled[/bold green]"
                    )

        return "\n".join((" - " + line for line in output))


class Module(EnumerateModule):
    """Enumerate the current PowerShell transcription settings on the target"""

    PROVIDES = ["powershell.transcription"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        registry_key = (
            "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
        )

        registry_values = {
            "EnableTranscripting": bool,
            "OutputDirectory": str,
            "EnableInvocationHeader": bool,
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

        yield PowerShellTranscription(self.name, registry_values)
