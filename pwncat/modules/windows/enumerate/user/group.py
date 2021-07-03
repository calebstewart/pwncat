#!/usr/bin/env python3

import pwncat
from pwncat.modules import ModuleFailed
from pwncat.facts.windows import WindowsGroup
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class Module(EnumerateModule):
    """Enumerate groups from a windows target"""

    PROVIDES = ["group"]
    PLATFORM = [Windows]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):
        """Yield WindowsGroup objects"""

        try:
            groups = session.platform.powershell("Get-LocalGroup")
            if not groups:
                raise ModuleFailed("no groups returned from Get-LocalGroup")
        except PowershellError as exc:
            raise ModuleFailed(str(exc)) from exc

        for group in groups[0]:
            try:
                members = session.platform.powershell(
                    f"Get-LocalGroupMember {group['Name']}"
                )
                if members:
                    members = (
                        [m["SID"] for m in members[0]]
                        if isinstance(members[0], list)
                        else [members[0]["SID"]["Value"]]
                    )
            except PowershellError:
                members = []

            yield WindowsGroup(
                source=self.name,
                name=group["Name"],
                gid=group["SID"],
                description=group["Description"],
                principal_source=group["PrincipalSource"],
                members=members,
            )
