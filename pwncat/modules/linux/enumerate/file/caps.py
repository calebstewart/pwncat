#!/usr/bin/env python3
import dataclasses
from typing import List

import rich.markup

import pwncat
from pwncat import util
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule

"""
TODO: Eventually, this should be used for escalation as well, because privilege
escalation can be performed with binary capabilities. These are not yet
implemented in our gtfobins.json database, but John can tackle that soon.
"""


class FileCapabilityData(Fact):
    def __init__(self, source, path, caps):
        super().__init__(source=source, types=["file.caps"])

        self.path: str = path
        """ The path to the file """
        self.caps: List[str] = caps
        """ List of strings representing the capabilities (e.g. "cap_net_raw+ep") """

    def title(self, session):
        line = f"[cyan]{rich.markup.escape(self.path)}[/cyan] -> ["
        line += ",".join(f"[blue]{rich.markup.escape(c)}[/blue]" for c in self.caps)
        line += "]"
        return line

    def __str__(self):
        line = f"[cyan]{rich.markup.escape(self.path)}[/cyan] -> ["
        line += ",".join(f"[blue]{rich.markup.escape(c)}[/blue]" for c in self.caps)
        line += "]"
        return line


class Module(EnumerateModule):
    """Enumerate capabilities of the binaries of the remote host"""

    PROVIDES = ["file.caps"]
    PLATFORM = [Linux]

    def enumerate(self, session):

        # Spawn a find command to locate the setuid binaries
        proc = session.platform.Popen(
            ["getcap", "-r", "/"],
            stderr=pwncat.subprocess.DEVNULL,
            stdout=pwncat.subprocess.PIPE,
            text=True,
        )

        # Process the standard output from the command
        with proc.stdout as stream:
            for path in stream:
                # Parse out path and capability list
                path, caps = [x.strip() for x in path.strip().split(" ")]
                caps = caps.split(",")

                fact = FileCapabilityData(self.name, path, caps)
                yield fact
