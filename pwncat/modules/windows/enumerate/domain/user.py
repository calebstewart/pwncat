#!/usr/bin/env python3
from typing import Dict, Optional
from datetime import datetime

import pwncat
from pwncat.modules import Status
from pwncat.facts.windows import WindowsUser
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class DomainUser(WindowsUser):
    """ Builds on Windows Groups to add domain specific information """

    def __init__(
        self,
        source: str,
        name: str,
        uid: str,
        account_expires: Optional[datetime],
        description: str,
        enabled: bool,
        full_name: str,
        password_changeable_date: Optional[datetime],
        password_expires: Optional[datetime],
        user_may_change_password: bool,
        password_required: bool,
        password_last_set: Optional[datetime],
        last_logon: Optional[datetime],
        principal_source: str,
        domain: str,
        data: Dict,
        password: Optional[str] = None,
        hash: Optional[str] = None,
    ):
        super().__init__(
            source=source,
            name=name,
            uid=uid,
            account_expires=account_expires,
            description=description,
            enabled=enabled,
            full_name=full_name,
            password_changeable_date=password_changeable_date,
            password_expires=password_expires,
            user_may_change_password=user_may_change_password,
            password_required=password_required,
            password_last_set=password_last_set,
            last_logon=last_logon,
            principal_source=principal_source,
            password=password,
            hash=hash,
        )

        self.types.append("domain.user")

        self.domain = domain

        if "description" in data:
            data["user_description"] = data.get("description")
            del data["description"]

        self.__dict__.update(data)

    def __repr__(self):
        if self.password is None and self.hash is None:
            return f"""DomainUser(uid={self.id}, name={repr(self.name)}, domain={repr(self.domain)})"""
        elif self.password is not None:
            return f"""DomainUser(uid={repr(self.id)}, name={repr(self.name)}, domain={repr(self.domain)}, password={repr(self.password)})"""
        else:
            return f"""DomainUser(uid={repr(self.id)}, name={repr(self.name)}, domain={repr(self.domain)}, hash={repr(self.hash)})"""


class Module(EnumerateModule):
    """ Retrieve information on all domain computers """

    PLATFORM = [Windows]
    PROVIDES = ["domain.user", "user"]
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
            domain = session.run("enumerate.domain")[0]
        except IndexError:
            # Not a domain joined machine
            return

        try:
            yield Status("requesting domain groups")
            users = session.platform.powershell("Get-DomainUser")[0]
        except (IndexError, PowershellError):
            # Doesn't appear to be a domain joined user
            return

        if isinstance(users, dict):
            users = [users]

        for user in users:
            yield DomainUser(
                source=self.name,
                name=user["samaccountname"],
                uid=user["objectsid"],
                account_expires=user.get("accountexpires"),
                description=user.get("description") or "",
                enabled=True,
                full_name=user.get("name") or "",
                password_changeable_date=None,
                password_expires=None,
                user_may_change_password=True,
                password_required=True,
                password_last_set=None,
                last_logon=None,
                principal_source="",
                domain=domain["Name"],
                data=user,
            )
