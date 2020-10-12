#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform import Platform
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class FileCapabilityData:

    path: str
    """ The path to the file """
    caps: List[str]
    """ List of strings representing the capabilities (e.g. "cap_net_raw+ep") """

    def __str__(self):
        line = f"[cyan]{self.path}[/cyan] -> [["
        line += ",".join(f"[blue]{c}[/blue]" for c in self.caps)
        line += "]]"
        return line


class Module(EnumerateModule):
    """ Enumerate capabilities of the binaries of the remote host """

    PROVIDES = ["file.caps"]
    PLATFORM = Platform.LINUX

    def enumerate(self):

        # Spawn a find command to locate the setuid binaries
        with pwncat.victim.subprocess(
            ["getcap", "-r", "/"], stderr="/dev/null", mode="r", no_job=True,
        ) as stream:
            for path in stream:
                # Parse out owner ID and path
                path, caps = [
                    x.strip() for x in path.strip().decode("utf-8").split(" = ")
                ]
                caps = caps.split(",")

                yield "file.caps", FileCapabilityData(path, caps)
