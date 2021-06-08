#!/usr/bin/env python3
from typing import Any, Dict
from collections import namedtuple

from pwncat.db import Fact
from pwncat.modules import Status, ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class SiteObject(Fact):
    def __init__(self, source: str, data: Dict):
        super().__init__(source=source, types=["domain.site"])

        self.site = data

    def __getitem__(self, name: str):
        """ Shortcut for getting properties from the `self.site` property. """

        return self.site[name]

    def title(self, session: "pwncat.manager.Session"):
        return f"[cyan]{self['distinguishedname']}[/cyan]"


class Module(EnumerateModule):
    """ Retrieve information on all domain computers """

    PLATFORM = [Windows]
    PROVIDES = ["domain.site"]
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
            yield Status("requesting domain sites")
            sites = session.platform.powershell("Get-DomainSite")[0]
        except (IndexError, PowershellError) as exc:
            # Doesn't appear to be a domain joined site
            return

        if isinstance(sites, dict):
            yield SiteObject(self.name, sites)
        else:
            yield from (SiteObject(self.name, site) for site in sites)
