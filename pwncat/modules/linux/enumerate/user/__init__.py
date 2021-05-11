#!/usr/bin/env python3

from pwncat.modules import ModuleFailed, Status
from pwncat.modules.enumerate import EnumerateModule, Schedule
from pwncat.platform.linux import Linux
from pwncat.facts.linux import LinuxUser


class Module(EnumerateModule):
    """Enumerate users from a linux target"""

    PROVIDES = ["user"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):

        passwd = session.platform.Path("/etc/passwd")
        shadow = session.platform.Path("/etc/shadow")
        users = {}

        try:
            with passwd.open("r") as filp:
                for user_info in filp:
                    try:
                        # Extract the user fields
                        (
                            name,
                            hash,
                            uid,
                            gid,
                            comment,
                            home,
                            shell,
                        ) = user_info.split(":")

                        # Build a user object
                        user = LinuxUser(
                            self.name,
                            name,
                            hash,
                            int(uid),
                            int(gid),
                            comment,
                            home,
                            shell,
                        )

                        users[name] = user
                        yield Status(user)

                    except Exception as exc:
                        # Bad passwd line
                        continue
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc

        try:
            with shadow.open("r") as filp:
                for user_info in filp:
                    try:
                        (
                            name,
                            hash,
                            last_change,
                            min_age,
                            max_age,
                            warn_period,
                            inactive_period,
                            expir_date,
                            reserved,
                        ) = user_info.split(":")

                        if users[name].hash is None:
                            users[name].hash = hash if hash != "" else None
                        if users[name].password is None and hash == "":
                            users[name].password = ""
                        users[name].last_change = int(last_change)
                        users[name].min_age = int(min_age)
                        users[name].max_age = int(max_age)
                        users[name].warn_period = int(warn_period)
                        users[name].inactive_period = int(inactive_period)
                        users[name].expiration = int(expir_date)
                        users[name].reserved = reserved
                    except:
                        continue
        except (FileNotFoundError, PermissionError):
            pass
        except Exception as exc:
            raise ModuleFailed(str(exc)) from exc

        # Yield all the known users after attempting to parse /etc/shadow
        yield from users.values()
