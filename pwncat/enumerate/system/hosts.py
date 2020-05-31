#!/usr/bin/env python3
import dataclasses
from typing import Generator, List
import re

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.system"
provides = "system.network.hosts"
per_user = False


@dataclasses.dataclass
class HostData(FactData):

    address: str
    hostnames: List[str]

    def __str__(self):
        return f"{Fore.CYAN}{self.address}{Fore.RESET} -> {Fore.BLUE}{self.hostnames}{Fore.RESET}"


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate hosts identified in /etc/hosts which are not localhost
    :return:
    """

    try:
        with pwncat.victim.open("/etc/hosts", "r") as filp:
            for line in filp:
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
                address, *names = [e for e in line.split(" ") if e != ""]
                yield HostData(address, names)
    except (PermissionError, FileNotFoundError):
        pass
