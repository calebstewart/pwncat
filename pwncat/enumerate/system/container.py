#!/usr/bin/env python3
import dataclasses
from typing import Generator

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.system"
provides = "system.container"
per_user = False


@dataclasses.dataclass
class ContainerData(FactData):

    type: str
    """ what type of container? either docker or lxd """

    def __str__(self):
        return f"Running in a {Fore.YELLOW}{self.type}{Fore.RESET} container"


def enumerate() -> Generator[FactData, None, None]:
    """
    Check if this system is inside a container
    :return:
    """

    try:
        with pwncat.victim.open("/proc/self/cgroup", "r") as filp:
            if "docker" in filp.read().lower():
                yield ContainerData("docker")
                return
    except (FileNotFoundError, PermissionError):
        pass

    with pwncat.victim.subprocess(
        f'find / -maxdepth 3 -name "*dockerenv*" -exec ls -la {{}} \\; 2>/dev/null', "r"
    ) as pipe:
        if pipe.read().strip() != b"":
            yield ContainerData("docker")
            return

    try:
        with pwncat.victim.open("/proc/1/environ", "r") as filp:
            if "container=lxc" in filp.read().lower():
                yield ContainerData("lxc")
                return
    except (FileNotFoundError, PermissionError):
        pass
