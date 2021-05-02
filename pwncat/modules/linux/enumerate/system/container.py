#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform.linux import Linux
from pwncat import util
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class ContainerData:

    type: str
    """ what type of container? either docker or lxd """

    def __str__(self):
        return f"Running in a [yellow]{self.type}[/yellow] container"


class Module(EnumerateModule):
    """
    Check if this system is inside a container
    :return:
    """

    PROVIDES = ["system.container"]
    PLATFORM = [Linux]

    def enumerate(self):

        try:
            with pwncat.victim.open("/proc/self/cgroup", "r") as filp:
                if "docker" in filp.read().lower():
                    yield "system.container", ContainerData("docker")
                    return
        except (FileNotFoundError, PermissionError):
            pass

        with pwncat.victim.subprocess(
            f'find / -maxdepth 3 -name "*dockerenv*" -exec ls -la {{}} \\; 2>/dev/null',
            "r",
        ) as pipe:
            if pipe.read().strip() != b"":
                yield "system.container", ContainerData("docker")
                return

        try:
            with pwncat.victim.open("/proc/1/environ", "r") as filp:
                if "container=lxc" in filp.read().lower():
                    yield "system.container", ContainerData("lxc")
                    return
        except (FileNotFoundError, PermissionError):
            pass
