#!/usr/bin/env python3

from pwncat.modules import ModuleFailed, Status
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.platform.linux import Linux, LinuxGroup


class Module(EnumerateModule):
    """Enumerate users from a linux target"""

    PROVIDES = ["group"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):

        group_file = session.platform.Path("/etc/group")

        try:
            with group_file.open("r") as filp:
                for group_line in filp:
                    try:
                        # Extract the group fields
                        (group_name, hash, gid, members) = group_line.split(":")

                        # Build a group object
                        group = LinuxGroup(
                            self.name,
                            group_name,
                            hash,
                            int(gid),
                            (m.strip() for m in members.split(",") if m.strip()),
                        )

                        yield group

                    except Exception as exc:
                        raise ModuleFailed(f"something fucked {exc}")
                        # Bad group line
                        continue

        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc
