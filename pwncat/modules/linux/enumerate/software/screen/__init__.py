#!/usr/bin/env python3
import os
import re
import shlex
import dataclasses

import pwncat
import rich.markup
from pwncat.db import Fact
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule

"""
TODO: This should realistically yield an ability (which can be used for 
privilege escalation)... but we can implement that later.
"""


class ScreenVersion(Fact):
    def __init__(self, source, path, perms, vulnerable):
        super().__init__(source=source, types=["software.screen.version"])

        self.path: str = path
        self.perms: int = perms
        self.vulnerable: bool = vulnerable

    def title(self, session):
        return f"[cyan]{rich.markup.escape(self.path)}[/cyan] (perms: [blue]{oct(self.perms)[2:]}[/blue]) [bold red]is vulnerable[/bold red]"


class Module(EnumerateModule):
    """
    Locate installations of the ``screen`` tool. This is useful because
    it may be vulnerable to a privilege escalation vulnerability depending
    on it's version.
    """

    PROVIDES = ["software.screen.version"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):
        """
        Enumerate locations of vulnerable screen versions
        :return:
        """

        # Grab current path plus other interesting paths
        paths = set(session.platform.getenv("PATH").split(":"))
        paths = paths | {
            "/bin",
            "/sbin",
            "/usr/local/bin",
            "/usr/local/sbin",
            "/usr/bin",
            "/usr/sbin",
        }

        # Look for matching binaries
        proc = session.platform.Popen(
            f"find {shlex.join(paths)} \\( -type f -or -type l \\) -executable \\( -name 'screen' -or -name 'screen-*' \\) -printf '%#m %p\\n' 2>/dev/null",
            shell=True,
            text=True,
            stdout=pwncat.subprocess.PIPE,
        )

        # First, collect all the paths to a `screen` binary we can find
        screen_paths = []
        for line in proc.stdout:
            line = line.strip()
            perms, *path = line.split(" ")
            path = " ".join(path)
            perms = int(perms, 8)

            # When the screen source code is on disk and marked as executable, this happens...
            if os.path.splitext(path)[1] in [".c", ".o", ".h"]:
                continue

            if perms & 0o4000:
                # if this is executable
                screen_paths.append((path, perms))

        # Clean up the search
        proc.wait()

        # Now, check each screen version to determine if it is vulnerable
        for screen_path, perms in screen_paths:
            version_output = session.platform.Popen(
                f"{screen_path} --version",
                shell=True,
                text=True,
                stdout=pwncat.subprocess.PIPE,
            )
            for line in version_output.stdout:
                # This process checks if it is a vulnerable version of screen
                match = re.search(r"(\d+\.\d+\.\d+)", line)
                if not match:
                    continue

                version_triplet = [int(x) for x in match.group().split(".")]

                if version_triplet[0] > 4:
                    continue

                if version_triplet[0] == 4 and version_triplet[1] > 5:
                    continue

                if (
                    version_triplet[0] == 4
                    and version_triplet[1] == 5
                    and version_triplet[2] >= 1
                ):
                    continue

                yield ScreenVersion(self.name, path, perms, vulnerable=True)

            # Clean up process
            version_output.wait()
