#!/usr/bin/env python3
import dataclasses
from typing import Generator, List

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.capabilities"
provides = "system.packages"
per_user = True
always_run = False


@dataclasses.dataclass
class PackageData(FactData):
    """
    Information describing an installed package
    """

    name: str
    version: str

    def __str__(self):
        line = f"{Fore.CYAN}{self.name}{Fore.RESET}"
        if self.version is not None:
            line += f" version {Fore.BLUE}{self.version}{Fore.RESET}"
        return line


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate installed packages agnostic to the underlying package manager

    :return: generator of package data
    """

    rpm = pwncat.victim.which("rpm")
    if rpm is not None:
        with pwncat.victim.subprocess(f"rpm -qa", "r") as filp:
            for line in filp:
                line = line.decode("utf-8").strip()
                if "-" in line:
                    line = line.split("-")
                    package = "-".join(line[:-1])
                    version = line[-1]
                else:
                    package = line
                    version = None
                yield PackageData(package, version)

    dpkg = pwncat.victim.which("dpkg")
    if dpkg is not None:
        with pwncat.victim.subprocess(f"dpkg -l", "r") as filp:
            line = ""
            try:
                while not line.startswith("+"):
                    line = next(filp).strip().decode("utf-8")
            except StopIteration:
                line = None
            if line is not None:
                for line in filp:
                    line = line.strip().decode("utf-8")
                    line = [c for c in line.split(" ") if c != ""]
                    # This shouldn't happen
                    if len(line) < 3:
                        continue
                    package = line[1]
                    version = line[2]
                    yield PackageData(package, version)
