#!/usr/bin/env python3
import subprocess
import dataclasses
from typing import Any

import pwncat
import rich.markup
from pwncat import util
from pwncat.db import Fact
from pwncat.modules import Status
from pwncat.gtfobins import Stream, Capability, BinaryNotFound
from pwncat.facts.ability import (GTFOExecute, GTFOFileRead, GTFOFileWrite,
                                  build_gtfo_ability)
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class Binary(Fact):
    """
    A generic description of a SUID binary
    """

    def __init__(self, source, path, uid):
        super().__init__(source=source, types=["file.suid"])

        """ The path to the binary """
        self.path: str = path

        """ The uid of the binary """
        self.uid: int = uid

    def title(self, session):
        color = "red" if self.uid == 0 else "green"
        return f"[cyan]{rich.markup.escape(self.path)}[/cyan] owned by [{color}]{rich.markup.escape(session.find_user(uid=self.uid).name)}[/{color}]"


class Module(EnumerateModule):
    """Enumerate SUID binaries on the remote host"""

    PROVIDES = [
        "file.suid",
        "ability.execute",
        "ability.file.read",
        "ability.file.write",
    ]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):

        # This forces the session to enumerate users FIRST, so we don't run
        # into trying to enumerate _whilest_ enumerating SUID binaries...
        # since we can't yet run multiple processes at the same time
        session.find_user(uid=0)

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

                fact = Binary(self.name, path, uid)
                yield fact

                yield from (
                    build_gtfo_ability(self.name, uid, method, suid=True)
                    for method in session.platform.gtfo.iter_binary(path)
                )
