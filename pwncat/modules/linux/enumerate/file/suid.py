#!/usr/bin/env python3
import subprocess
import dataclasses

import pwncat
from pwncat.platform.linux import Linux
from pwncat import util
from pwncat.modules import Status
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.modules.linux.enumerate.ability import (
    GTFOFileRead,
    GTFOFileWrite,
    GTFOExecute,
)
from pwncat.gtfobins import Capability, Stream, BinaryNotFound


@dataclasses.dataclass
class Binary:
    """
    A generic description of a SUID binary
    """

    path: str
    """ The path to the binary """
    owner: "pwncat.db.User"
    """ The owner of the binary """

    def __str__(self):
        color = "red" if self.owner.id == 0 else "green"
        return f"[cyan]{self.path}[/cyan] owned by [{color}]{self.owner.name}[/{color}]"

    @property
    def uid(self):
        return self.owner.id


class Module(EnumerateModule):
    """ Enumerate SUID binaries on the remote host """

    PROVIDES = ["file.suid", "ability.execute", "ability.read", "ability.write"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):

        # Spawn a find command to locate the setuid binaries
        proc = session.platform.Popen(
            ["find", "/", "-perm", "-4000", "-printf", "%U %p\\n"],
            stderr=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            text=True,
        )

        facts = []
        with proc.stdout as stream:
            for path in stream:
                # Parse out owner ID and path
                path = path.strip().split(" ")
                uid, path = int(path[0]), " ".join(path[1:])

                facts.append(Binary(path, uid))
                yield Status(path)

        for fact in facts:
            fact.owner = session.platform.find_user(id=fact.owner)
            yield "file.suid", fact
