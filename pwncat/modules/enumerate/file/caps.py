#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform.linux import Linux
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class FileCapabilityData:

    path: str
    """ The path to the file """
    caps: List[str]
    """ List of strings representing the capabilities (e.g. "cap_net_raw+ep") """

    def __str__(self):
        line = f"[cyan]{self.path}[/cyan] -> ["
        line += ",".join(f"[blue]{c}[/blue]" for c in self.caps)
        line += "]"
        return line


class Module(EnumerateModule):
    """ Enumerate capabilities of the binaries of the remote host """

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
                path, caps = [x.strip() for x in path.strip().split(" = ")]
                caps = caps.split(",")

                yield "file.caps", FileCapabilityData(path, caps)
