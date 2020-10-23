#!/usr/bin/env python3
import dataclasses

import pwncat
from pwncat.platform.linux import Linux
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class Binary:
    """
    A generic description of a SUID binary
    """

    path: str
    """ The path to the binary """
    uid: int
    """ The owner of the binary """

    def __str__(self):
        color = "red" if self.owner.id == 0 else "green"
        return f"[cyan]{self.path}[/cyan] owned by [{color}]{self.owner.name}[/{color}]"

    @property
    def owner(self):
        return pwncat.victim.find_user_by_id(self.uid)


class Module(EnumerateModule):
    """ Enumerate SUID binaries on the remote host """

    PROVIDES = ["file.suid"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self):

        # Spawn a find command to locate the setuid binaries
        with pwncat.victim.subprocess(
            ["find", "/", "-perm", "-4000", "-printf", "%U %p\\n"],
            stderr="/dev/null",
            mode="r",
            no_job=True,
        ) as stream:
            for path in stream:
                # Parse out owner ID and path
                path = path.strip().decode("utf-8").split(" ")
                uid, path = int(path[0]), " ".join(path[1:])

                yield "file.suid", Binary(path, uid)
