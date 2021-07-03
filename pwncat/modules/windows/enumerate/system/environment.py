#!/usr/bin/env python3


import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class EnvironmentData(Fact):
    def __init__(self, source, variable: str, value: str):
        super().__init__(source=source, types=["system.environment"])

        self.variable: bool = variable
        self.value: str = value

    def title(self, session):
        return f"[cyan]{rich.markup.escape(self.variable)}[/cyan] = [blue]{rich.markup.escape(self.value)} [/blue]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.environment"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                "Get-ChildItem env:\\ | Select Name,Value"
            )

            if not result:
                raise ModuleFailed("failed to retrieve env: PSDrive")

            environment = result[0]

        except PowershellError as exc:
            raise ModuleFailed("failed to retrieve env: PSDrive") from exc

        for pair in environment:
            yield EnvironmentData(self.name, pair["Name"], pair["Value"])
