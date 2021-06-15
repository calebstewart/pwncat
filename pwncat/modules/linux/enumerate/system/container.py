#!/usr/bin/env python3

from pwncat.db import Fact
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule


class ContainerData(Fact):
    def __init__(self, source, system):
        super().__init__(source=source, types=["system.container"])

        self.system: str = system
        """ what type of container? either docker or lxd """

    def title(self, session):
        return f"[yellow]{self.system}[/yellow]"


class Module(EnumerateModule):
    """
    Check if this system is inside a container
    :return:
    """

    PROVIDES = ["system.container"]
    PLATFORM = [Linux]

    def enumerate(self, session):

        try:
            with session.platform.open("/proc/self/cgroup", "r") as filp:
                if "docker" in filp.read().lower():
                    yield ContainerData(self.name, "docker")
                    return
        except (FileNotFoundError, PermissionError):
            pass

        try:
            proc = session.platform.run(
                'find / -maxdepth 3 -name "*dockerenv*" -exec ls -la {{}} \\; 2>/dev/null',
                capture_output=True,
                text=True,
            )

            if proc.stdout:
                if proc.stdout.strip() != "":
                    yield ContainerData(self.name, "docker")
                    return

        except CalledProcessError:
            # We couldn't read in from a .dockerenv file
            pass

        try:
            with session.platform.open("/proc/1/environ", "r") as filp:
                if "container=lxc" in filp.read().lower():
                    yield ContainerData(self.name, "lxc")
                    return
        except (FileNotFoundError, PermissionError):
            pass
