#!/usr/bin/env python3
from typing import Any, Dict, List, Optional
from collections import namedtuple

from pwncat.db import Fact
from pwncat.modules import Status, ModuleFailed
from pwncat.facts.windows import WindowsGroup
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class DomainGroup(WindowsGroup):
    """ Builds on Windows Groups to add domain specific information """

    def __init__(self, source: str, domain: str, data: Dict, members: List[str]):
        super().__init__(
            source=source,
            name=data["samaccountname"],
            gid=data["objectsid"],
            description=data.get("description"),
            principal_source=None,
            domain=domain,
            members=members,
        )

        self.types.append("domain.group")

        self.grouptype: int = data.get("grouptype") or 0
        self.samaccounttype: int = data.get("samaccounttype") or 0
        self.objectclass: List[str] = data.get("objectclass") or []
        self.cn: str = data.get("cn") or None
        self.distinguishedname: Optional[str] = data.get("distinguishedname") or None
        self.objectcategory: str = data.get("objectcategory")

    def title(self, session: "pwncat.manager.Session"):

        members = []
        for uid in self.members:
            user = session.find_user(uid=uid)
            if user is None:
                user = session.find_group(gid=uid)

            if user is None:
                members.append(f"UID({repr(uid)})")
            else:
                members.append(user.name)

        return f"""DomainGroup(gid={repr(self.id)}, name={repr(self.name)}, domain={repr(self.domain)}, members={repr(members)})"""


class Module(EnumerateModule):
    """ Retrieve information on all domain computers """

    PLATFORM = [Windows]
    PROVIDES = ["domain.group", "group"]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):
        """ Perform enumeration """

        # Ensure we have PowerView loaded
        yield Status("loading powersploit recon")
        session.run("powersploit", group="recon")

        try:
            domain = session.run("enumerate.domain")[0]
        except IndexError:
            # Not a domain joined machine
            return

        try:
            yield Status("requesting domain groups")
            groups = session.platform.powershell("Get-DomainGroup")[0]
        except (IndexError, PowershellError) as exc:
            # Doesn't appear to be a domain joined group
            return

        if isinstance(groups, dict):
            groups = [groups]

        for group in groups:

            try:
                yield Status(
                    f"[cyan]{group['samaccountname']}[/cyan]: requesting members"
                )
                members = session.platform.powershell(
                    f"Get-DomainGroupMember \"{group['samaccountname']}\""
                )[0]

                if isinstance(members, dict):
                    members = [members]

            except (IndexError, PowershellError) as exc:
                members = []

            members = [member["MemberSID"] for member in members]

            yield DomainGroup(
                self.name, domain=domain["Name"], data=group, members=members
            )
