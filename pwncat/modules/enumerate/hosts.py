#!/usr/bin/env python3
from typing import List
import dataclasses
import re

import pwncat
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule

@dataclasses.dataclass
class HostData:

    address: str
    hostnames: List[str]

    def __str__(self):
        joined_hostnames = ", ".join(self.hostnames)
        return f"[cyan]{self.address}[/cyan] -> [blue]{joined_hostnames}[/blue]"

class Module(EnumerateModule):
    """
    Enumerate hosts identified in /etc/hosts which are not localhost
    :return:
    """

    PROVIDES = ["hosts"]

    def enumerate(self):

        try:
            with pwncat.victim.open("/etc/hosts", "r") as filp:
                for line in filp:
                    # Remove comments
                    line = re.sub(r"#.*$", "", line).strip()
                    line = line.replace("\t", " ")
                    # We don't care about localhost or localdomain entries
                    if (
                        line.endswith("localhost")
                        or line.endswith(".localdomain")
                        or line.endswith("localhost6")
                        or line.endswith(".localdomain")
                        or line.endswith("localhost4")
                        or line.endswith("localdomain4")
                        or line == ""
                    ):
                        continue
                    address, *hostnames = [e for e in line.split(" ") if e != ""]
                    yield "hosts", HostData(address, hostnames)
        except (PermissionError, FileNotFoundError):  
            pass
