#!/usr/bin/env python3
from typing import Any, Dict
from collections import namedtuple

from pwncat.db import Fact
from pwncat.modules import Status, ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class Module(EnumerateModule):
    """ Retrieve information on all domain computers """

    PLATFORM = [Windows]
    PROVIDES = ["domain.fileserver"]
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
            yield Status("requesting domain file servers")
            names = session.platform.powershell("Get-DomainFileServer")[0]
        except (IndexError, PowershellError) as exc:
            return

        if not isinstance(names, list):
            names = [names]

        names = [name.lower() for name in names]

        for computer in session.run("enumerate.domain.computer"):
            if computer["name"].lower() in names:
                yield computer
