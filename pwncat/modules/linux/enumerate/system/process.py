#!/usr/bin/env python3
from typing import List
import dataclasses
import shlex

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class ProcessData:
    """ A single process from the `ps` output """

    uid: int
    pid: int
    ppid: int
    argv: List[str]

    def __str__(self):
        if isinstance(self.uid, str):
            user = self.uid
            color = "yellow"
        else:
            if self.uid == 0:
                color = "red"
            elif self.uid < 1000:
                color = "blue"
            else:
                color = "magenta"

            # Color our current user differently
            if self.uid == pwncat.victim.current_user.id:
                color = "lightblue"

            user = self.user.name

        result = f"[{color}]{user:>10s}[/{color}] "
        result += f"[magenta]{self.pid:<7d}[/magenta] "
        result += f"[lightblue]{self.ppid:<7d}[/lightblue] "
        result += f"[cyan]{shlex.join(self.argv)}[/cyan]"

        return result

    @property
    def user(self) -> pwncat.db.User:
        return pwncat.victim.find_user_by_id(self.uid)


class Module(EnumerateModule):
    """
    Extract the currently running processes. This will parse the
    process information and give you access to the user, parent
    process, command line, etc as with the `ps` command.

    This is only run once unless manually cleared.
    """

    PROVIDES = ["system.process"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self):

        try:
            with pwncat.victim.subprocess(
                ["ps", "-eo", "pid,ppid,user,command", "--no-header", "-ww"], "r"
            ) as filp:
                # Iterate over each process
                for line in filp:
                    line = line.strip().decode("utf-8")

                    entities = line.split()
                    pid, ppid, username, *argv = entities
                    if username not in pwncat.victim.users:
                        uid = username
                    else:
                        uid = pwncat.victim.users[username].id

                    command = " ".join(argv)
                    # Kernel threads aren't helpful for us
                    if command.startswith("[") and command.endswith("]"):
                        continue

                    pid = int(pid)
                    ppid = int(ppid)

                    yield "system.process", ProcessData(uid, pid, ppid, argv)
        except (FileNotFoundError, PermissionError):
            return
