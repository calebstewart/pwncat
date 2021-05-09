#!/usr/bin/env python3
from typing import List
import dataclasses
import re

import rich.markup

import pwncat
from pwncat import util
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule


class HostData(Fact):
    def __init__(self, source, address, hostnames):
        super().__init__(source=source, types=["system.mountpoint"])

        self.address: str = address
        self.hostnames: List[str] = hostnames

    def title(self, session):
        joined_hostnames = ", ".join((rich.markup.escape(h) for h in self.hostnames))
        return f"[cyan]{rich.markup.escape(self.address)}[/cyan] -> [blue]{joined_hostnames}[/blue]"


class Module(EnumerateModule):
    """
    Enumerate hosts identified in /etc/hosts which are not localhost
    :return:
    """

    PROVIDES = ["network.hosts"]
    PLATFORM = [Linux]

    def enumerate(self, session):

        try:
            with session.platform.open("/etc/hosts", "r") as filp:
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
                    yield HostData(self.name, address, hostnames)
        except (PermissionError, FileNotFoundError):
            pass
