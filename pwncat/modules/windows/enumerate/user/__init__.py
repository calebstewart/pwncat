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
                domain=None,
            )

        try:
            result = session.platform.powershell(
                "(Get-WmiObject Win32_ComputerSystem).PartOfDomain"
            )[0]
        except (KeyError, PowershellError):
            # Unable to grab domain status
            return

        # Not in a domain
        if not result:
            return

        # We are in a domain, load powerview
        session.run("powersploit", group="recon")

        try:
            results = session.platform.powershell("Get-DomainUser")[0]
        except (KeyError, PowershellError):
            # We coudln't retrieve domain users :(
            return

        if isinstance(results, dict):
            results = [results]

        for user in results:

            dn = user.get("distinguishedname")
            if dn is None:
                domain = "unknown"
            else:
                dn = dn.split(",")
                domain = []
                for element in dn[::-1]:
                    if element.startswith("DC="):
                        domain.insert(0, element.split("=")[1])
                    else:
                        break

                domain = ".".join(domain)

            yield WindowsUser(
                source=self.name,
                name=user["samaccountname"],
                uid=user["objectsid"],
                account_expires=None,
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
                domain=domain,
            )
