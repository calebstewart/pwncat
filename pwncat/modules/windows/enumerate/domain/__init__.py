#!/usr/bin/env python3
from typing import Dict

import pwncat
from pwncat.db import Fact
from pwncat.modules import Status
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class DomainObject(Fact):
    def __init__(self, source: str, data: Dict, sid: str):
        super().__init__(source=source, types=["domain.details"])

        self.domain = data
        self.sid = sid

    def __getitem__(self, name: str):
        """Shortcut for getting properties from the `self.domain` property."""

        return self.domain[name]

    def title(self, session: "pwncat.manager.Session"):
        return f"Active Dirctory Domain: [magenta]{self.domain['Name']}[/magenta]"

    def description(self, session: "pwncat.manager.Session"):
        output = []

        output.append(f"Forest: [cyan]{self['Forest']['Name']}[/cyan]")
        output.append(
            f"Domain Controllers: [cyan]{'[/cyan][cyan]'.join(self['DomainControllers'])}[/cyan]"
        )
        output.append(f"SID: {repr(self.sid)}")

        return "\n".join(output)


class Module(EnumerateModule):
    """Retrieve domain membership information"""

    PLATFORM = [Windows]
    PROVIDES = ["domain.details"]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):
        """Perform enumeration"""

        # Ensure we have PowerView loaded
        yield Status("loading powersploit recon")
        session.run("powersploit", group="recon")

        try:
            yield Status("requesting domain details")
            domain = session.platform.powershell("Get-Domain")[0]
        except (IndexError, PowershellError):
            # Doesn't appear to be a domain joined computer
            return

        try:
            yield Status("requesting domain sid")
            sid = session.platform.powershell("Get-DomainSID")[0]
        except (IndexError, PowershellError):
            sid = None

        yield DomainObject(self.name, domain, sid)
