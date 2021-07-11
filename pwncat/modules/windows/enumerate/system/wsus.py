#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule
from pwncat.modules.windows.enumerate import build_powershell_enumeration


def wsus_title(self, session: "pwncat.manager.Session"):
    return rich.markup.escape(self.server)


Module = build_powershell_enumeration(
    types=["system.wsus.server"],
    schedule=Schedule.ONCE,
    command="Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer",
    docstring="Locate all WSUS update server",
    title=wsus_title,
    description=None,
    single=True,
)

# class WindowsUpdateServer(Fact):
#     def __init__(self, source: str, server: str):
#         super().__init__(source=source, types=["system.wsus.server"])
#
#         self.server = server
#
#     def is_secure(self) -> bool:
#         """Check if the given server is secure"""
#         return self.server.startswith("https://")
#
#     def title(self, session):
#         return rich.markup.escape(self.server)
#
#
# class Module(EnumerateModule):
#     """Locate all WSUS update servers"""
#
#     PROVIDES = ["system.wsus.server"]
#     PLATFORM = [Windows]
#     SCHEDULE = Schedule.ONCE
#
#     def enumerate(self, session: "pwncat.manager.Session"):
#
#         try:
#             result = session.platform.powershell(
#                 "Get-ItemPropertyValue -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate' -Name WUServer"
#             )
#             if not result:
#                 return
#
#             yield WindowsUpdateServer(source=self.name, server=result[0])
#         except PowershellError as exc:
#             pass
