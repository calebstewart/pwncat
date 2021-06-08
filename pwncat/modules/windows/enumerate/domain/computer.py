#!/usr/bin/env python3
from typing import Any, Dict
from collections import namedtuple

from pwncat.db import Fact
from pwncat.modules import Status, ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class ComputerObject(Fact):
    def __init__(self, source: str, data: Dict):
        super().__init__(source=source, types=["domain.computer"])

        self.computer = data

    def __getitem__(self, name: str):
        """ Shortcut for getting properties from the `self.domain` property. """

        return self.computer[name]

    def title(self, session: "pwncat.manager.Session"):
        return f"[blue]{self['dnshostname']}[/blue] ([cyan]{self['name']}[/cyan])"

    def is_dc(self):
        """ Query if this computer object is a domain controller """

        uac = self.computer.get("useraccountcontrol") or 0

        return (uac & 0x2000) > 0

    def is_rodc(self):
        """ Query if this computer object is a read only domain controller """

        uac = self.computer.get("useraccountcontrol") or 0

        return (uac & 0x04000000) > 0

    def description(self, session: "pwncat.manager.Session"):
        output = []

        if self.is_rodc():
            output.append("[red]Read-Only Domain Controller[/red]")
        elif self.is_dc():
            output.append("[bold red]Domain Controller[/bold red]")

        output.append(f"Computer SID: [cyan]{self['objectsid']}[/cyan]")
        output.append(f"Machine Account: [cyan]{self['samaccountname']}[/cyan]")
        output.append(
            f"Operating System: [blue]{self['operatingsystem']} {self['operatingsystemversion']}[/blue]"
        )
        output.append(
            f"Distinguished Name: [magenta]{self['distinguishedname']}[/magenta]"
        )

        return "\n".join(output)


class Module(EnumerateModule):
    """ Retrieve information on all domain computers """

    PLATFORM = [Windows]
    PROVIDES = ["domain.computer"]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):
        """ Perform enumeration """

        # Check that we are in a domain
        if not session.run("enumerate", types=["domain.details"]):
            return

        # Ensure we have PowerView loaded
        yield Status("loading powersploit recon")
        session.run("powersploit", group="recon")

        try:
            yield Status("requesting domain computers")
            computers = session.platform.powershell("Get-DomainComputer")[0]
        except (IndexError, PowershellError) as exc:
            # Doesn't appear to be a domain joined computer
            return

        if isinstance(computers, dict):
            yield ComputerObject(self.name, computers)
        else:
            yield from (ComputerObject(self.name, computer) for computer in computers)
