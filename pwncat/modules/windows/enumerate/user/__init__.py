#!/usr/bin/env python3

from pwncat.modules import Status, ModuleFailed
from pwncat.facts.windows import WindowsUser
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class Module(EnumerateModule):
    """ Enumerate users from a windows target """

    PROVIDES = ["user"]
    PLATFORM = [Windows]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):

        try:
            users = session.platform.powershell("Get-LocalUser")
            if not users:
                raise ModuleFailed("no users returned from Get-Localuser")
        except PowershellError as exc:
            raise ModuleFailed(str(exc)) from exc

        users = users[0]

        for user in users:
            yield WindowsUser(
                source=self.name,
                name=user["Name"],
                uid=user["SID"],
                account_expires=None,
                description=user["Description"],
                enabled=user["Enabled"],
                full_name=user["FullName"],
                password_changeable_date=None,
                password_expires=None,
                user_may_change_password=user["UserMayChangePassword"],
                password_required=user["PasswordRequired"],
                password_last_set=None,
                last_logon=None,
                principal_source=user["PrincipalSource"],
            )

        well_known = {
            "S-1-0-0": "NULL AUTHORITY\\NOBODY",
            "S-1-1-0": "WORLD AUTHORITY\\Everyone",
            "S-1-2-0": "LOCAL AUTHORITY\\Local",
            "S-1-3-0": "CREATOR AUTHORITY\\Creator Owner",
            "S-1-3-1": "CREATOR AUTHORITY\\Creator Group",
            "S-1-3-4": "CREATOR AUTHORITY\\Owner Rights",
            "S-1-4": "NONUNIQUE AUTHORITY",
            "S-1-5-1": "NT AUTHORITY\\DIALUP",
            "S-1-5-2": "NT AUTHORITY\\NETWORK",
            "S-1-5-3": "NT AUTHORITY\\BATCH",
            "S-1-5-4": "NT AUTHORITY\\INTERACTIVE",
            "S-1-5-6": "NT AUTHORITY\\SERVICE",
            "S-1-5-7": "NT AUTHORITY\\ANONYMOUS",
            "S-1-5-9": "NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS",
            "S-1-5-10": "NT AUTHORITY\\PRINCIPAL SELF",
            "S-1-5-11": "NT AUTHORITY\\AUTHENTICATED USERS",
            "S-1-5-12": "NT AUTHORITY\\RESTRICTED CODE",
            "S-1-5-13": "NT AUTHORITY\\TERMINAL SERVER USERS",
            "S-1-5-14": "NT AUTHORITY\\REMOTE INTERACTIVE LOGON",
            "S-1-5-17": "NT AUTHORITY\\IUSR",
            "S-1-5-18": "NT AUTHORITY\\SYSTEM",
            "S-1-5-19": "NT AUTHORITY\\LOCAL SERVICE",
            "S-1-5-20": "NT AUTHORITY\\NETWORK SERVICE",
        }

        for sid, name in well_known.items():
            yield WindowsUser(
                source=self.name,
                name=name,
                uid=sid,
                account_expires=None,
                description=None,
                enabled=True,
                full_name=name,
                password_changeable_date=None,
                password_expires=None,
                user_may_change_password=None,
                password_required=None,
                password_last_set=None,
                last_logon=None,
                principal_source="well known sid",
                well_known=True,
            )
