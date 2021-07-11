#!/usr/bin/env python3
from typing import Any, Dict

import rich.markup

from pwncat.modules.enumerate import Schedule
from pwncat.modules.windows.enumerate import build_powershell_enumeration


def startup_title(self, session: "pwncat.manager.Session"):
    return f"[cyan]{rich.markup.escape(self.Caption)}[/cyan]: {repr(rich.markup.escape(self.Command))}"


Module = build_powershell_enumeration(
    types=["system.startup.command"],
    schedule=Schedule.ONCE,
    command="Get-CimInstance -ClassName Win32_StartupCommand",
    docstring="Locate all startup commands via WMI queries",
    title=startup_title,
    description=None,
    single=False,
)
