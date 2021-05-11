#!/usr/bin/env python3
import shlex
import dataclasses
from typing import List

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class ProcessData(Fact):

    """A single process from the `ps` output"""

    def __init__(self, source, uid, username, pid, ppid, argv):
        super().__init__(source=source, types=["system.process"])

        self.uid: int = uid
        self.username: str = username
        self.pid: int = pid
        self.ppid: int = ppid
        self.argv: List[str] = argv

    def title(self, session):
        if self.uid == 0:
            color = "red"
        elif self.uid < 1000:
            color = "blue"
        else:
            color = "magenta"

        # Color our current user differently
        if self.uid == session.platform.getuid():
            color = "lightblue"

        result = f"[{color}]{self.username:>10s}[/{color}] "
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

        try:
            proc = session.platform.run(
                "ps -eo pid,ppid,uid,user,command --no-header -ww",
                capture_output=True,
                text=True,
            )

            if proc.stdout:
                # Iterate over each process
                for line in proc.stdout.split("\n"):
                    if line:
                        line = line.strip()

                        entities = line.split()

                        try:
                            pid, ppid, uid, username, *argv = entities
                        except ValueError as exc:
                            # We couldn't parse some line for some reason?
                            continue

                        command = " ".join(argv)
                        # Kernel threads aren't helpful for us
                        if command.startswith("[") and command.endswith("]"):
                            continue

                        uid = int(uid)
                        pid = int(pid)
                        ppid = int(ppid)

                        yield ProcessData(self.name, uid, username, pid, ppid, argv)
        except (FileNotFoundError, PermissionError):
            return
