#!/usr/bin/env python3
from typing import List
import dataclasses
import shlex

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule


class ProcessData(Fact):

    """A single process from the `ps` output"""

    def __init__(self, source, uid, pid, ppid, argv):
        super().__init__(source=source, types=["system.process"])

        self.uid: int = uid
        self.pid: int = pid
        self.ppid: int = ppid
        self.argv: List[str] = argv

    def title(self, session):
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
            if self.uid == session.platform.getuid():
                color = "lightblue"

            user = session.find_user(uid=self.uid)
            if user is not None:
                user = user.name
            else:
                user = self.uid

        result = f"[{color}]{user:>10s}[/{color}] "
        result += f"[magenta]{self.pid:<7d}[/magenta] "
        result += f"[lightblue]{self.ppid:<7d}[/lightblue] "
        result += f"[cyan]{shlex.join(self.argv)}[/cyan]"

        return result


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

    def enumerate(self, session):

        # This forces the session to enumerate users FIRST, so we don't run
        # into trying to enumerate _whilest_ enumerating SUID binaries...
        # since we can't yet run multiple processes at the same time
        session.find_user(uid=0)

        try:
            proc = session.platform.run(
                "ps -eo pid,ppid,user,command --no-header -ww",
                capture_output=True,
                text=True,
            )

            if proc.stdout:
                # Iterate over each process
                for line in proc.stdout.split("\n"):
                    if line:
                        line = line.strip()

                        entities = line.split()

                        pid, ppid, username, *argv = entities

                        uid = session.find_user(name=username)
                        if uid is not None:
                            uid = uid.id
                        else:
                            uid = username

                        command = " ".join(argv)
                        # Kernel threads aren't helpful for us
                        if command.startswith("[") and command.endswith("]"):
                            continue

                        pid = int(pid)
                        ppid = int(ppid)

                        yield ProcessData(self.name, uid, pid, ppid, argv)
        except (FileNotFoundError, PermissionError):
            return
