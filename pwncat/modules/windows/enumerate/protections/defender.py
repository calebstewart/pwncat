#!/usr/bin/env python3

from typing import Any, Dict

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class DefenderData(Fact):
    def __init__(self, source, configuration: Dict):
        super().__init__(source=source, types=["protections.defender"])

        self._configuration: Any = configuration
        """ The huge dictionary that Windows Defender returns"""

    def __getitem__(self, name):
        return self._configuration[name]

    @property
    def enabled(self) -> bool:
        return not self._configuration["DisableRealtimeMonitoring"]

    def title(self, session):

        if self.enabled:
            return "Windows Defender is [bold red]enabled[/bold red]"

        return "Windows Defender is [bold green]disabled[/bold green]"

    def description(self, session):
        output = []
        if self._configuration["ExclusionPath"]:
            output.append("[bold]Excluded paths:[/bold]")
            for path in self._configuration["ExclusionPath"]:
                output.append(f" - {rich.markup.escape(path)}")

        if not output:
            return None

        return "\n".join(output)


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["protections.defender"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        if not session.platform.is_admin():
            session.log(
                "[yellow]protections warning[/yellow]: not all Defender data can be received without admin privileges"
            )

        try:
            result = session.platform.powershell("Get-MpPreference", depth=5)
            # session.print(result[0])

            if not result:
                raise ModuleFailed("could not retrieve Get-MpPreference")

            yield DefenderData(self.name, result[0])

        except PowershellError as exc:
            raise ModuleFailed(f"could not retrieve Get-MpPreference: {exc}") from exc
