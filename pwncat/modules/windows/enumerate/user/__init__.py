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
