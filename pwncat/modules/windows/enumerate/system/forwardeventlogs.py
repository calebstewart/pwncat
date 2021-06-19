#!/usr/bin/env python3


import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class ForwardEventLogData(Fact):
    def __init__(self, source, string: str):
        super().__init__(source=source, types=["system.forwardeventlogs"])

        self.string = string
        self.configured = bool(string)  # if it is configured, set it
        if self.configured:
            for setting in self.string.split(","):
                variable, value = setting.split("=")
                setattr(self, variable, value)

    def title(self, session):
        output = "Event log forwarding is "
        if self.configured:
            output += "[bold red]enabled[/bold red]"
        else:
            output += "[bold green]not configured[/bold green]"
        return output

    def description(self, session):
        output = []
        if self.configured:
            for setting in self.string.split(","):
                variable, value = setting.split("=")
                output.append(
                    f"'{rich.markup.escape(variable)}' = {rich.markup.escape(str(value))}"
                )
        output = "\n".join((" - " + line for line in output))
        if not output:
            return None
        return output


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.forwardeventlogs"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                "Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\EventLog\\EventForwarding\\SubscriptionManager'"
            )

            if not result:
                result = ""
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
                        yield ForwardEventLogData(self.name, value)

        except PowershellError as exc:
            if "does not exist" in exc.message:
                result = ""  # registry path does not exist... not configured
            else:
                raise ModuleFailed(
                    "failed to retrieve SubscriptionManager registry key"
                ) from exc

        yield ForwardEventLogData(self.name, result)
