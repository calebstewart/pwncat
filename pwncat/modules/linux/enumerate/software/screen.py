#!/usr/bin/env python3
import dataclasses
import os
import re
import shlex

import pwncat
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.platform.linux import Linux


@dataclasses.dataclass
class ScreenVersion:

    path: str
    perms: int
    vulnerable: bool = True

    def __str__(self):
        return f"[cyan]{self.path}[/cyan] (perms: [blue]{oct(self.perms)[2:]}[/blue])"


class Module(EnumerateModule):
    """
    Locate installations of the ``screen`` tool. This is useful because
    it may be vulnerable to a privilege escalation vulnerability depending
    on it's version.
    """

    PROVIDES = ["software.screen.version"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self):
        """
        Enumerate kernel/OS version information
        :return:
        """

        # Grab current path plus other interesting paths
        paths = set(pwncat.victim.getenv("PATH").split(":"))
        paths = paths | {
            "/bin",
            "/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/bin",
            "/usr/sbin",
        }

        # Look for matching binaries
        with pwncat.victim.subprocess(
            f"find {shlex.join(paths)} \\( -type f -or -type l \\) -executable \\( -name 'screen' -or -name 'screen-*' \\) -printf '%#m %p\\n' 2>/dev/null"
        ) as pipe:
            for line in pipe:
                line = line.decode("utf-8").strip()
                perms, *path = line.split(" ")
                path = " ".join(path)
                perms = int(perms, 8)

                # When the screen source code is on disk and marked as executable, this happens...
                if os.path.splitext(path)[1] in [".c", ".o", ".h"]:
                    continue

                yield "software.screen.version", ScreenVersion(path, perms)
