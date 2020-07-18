#!/usr/bin/env python3
import dataclasses
from typing import Generator, List

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.capabilities"
provides = "file.caps"
per_user = True
always_run = False


@dataclasses.dataclass
class FileCapabilityData(FactData):

    path: str
    """ The path to the file """
    caps: List[str]
    """ List of strings representing the capabilities (e.g. "cap_net_raw+ep") """

    def __str__(self):
        line = f"[cyan]{self.path}[/cyan] -> [["
        line += ",".join(f"[blue]{c}[/blue]" for c in self.caps)
        line += "]]"
        return line


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate executables with assigned capabilities

    :return: generator of FileCapability data
    """

    if pwncat.victim.which("getcap") is None:
        return

    with pwncat.victim.subprocess(f"getcap -r / 2>/dev/null", "r") as filp:
        for line in filp:
            line = line.strip().decode("utf-8")
            # I don't know why this would happen, but just in case
            if " = " not in line:
                continue

            filename, caps = [x.strip() for x in line.split(" = ")]
            caps = caps.split(",")

            yield FileCapabilityData(filename, caps)
