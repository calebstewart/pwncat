#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform import Platform
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class DistroVersionData:
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.

    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    name: str
    ident: str
    build_id: str
    version: str

    def __str__(self):
        return (
            f"Running [blue]{self.name}[/blue] ([cyan]{self.ident}[/cyan]), "
            f"Version [red]{self.version}[/red], "
            f"Build ID [green]{self.build_id}[/green]."
        )


class Module(EnumerateModule):
    """
    Enumerate OS/Distribution version information
    """

    PROVIDES = ["system.distro"]
    PLATFORM = Platform.LINUX

    def enumerate(self):

        build_id = None
        pretty_name = None
        ident = None
        version = None

        try:
            with pwncat.victim.open("/etc/os-release", "r") as filp:
                for line in filp:
                    line = line.strip()
                    if line.startswith("PRETTY_NAME="):
                        pretty_name = line.split("=")[1].strip('"')
                    elif line.startswith("BUILD_ID="):
                        build_id = line.split("=")[1].strip('"')
                    elif line.startswith("ID="):
                        ident = line.split("=")[1].strip('"')
                    elif line.startswith("VERSION_ID="):
                        version = line.split("=")[1].strip('"')
        except (PermissionError, FileNotFoundError):
            pass

        if version is None:
            try:
                with pwncat.victim.open("/etc/lsb-release", "r") as filp:
                    for line in filp:
                        if line.startswith("LSB_VERSION="):
                            version = line.split("=")[1].strip('"')
                            break
            except (PermissionError, FileNotFoundError):
                pass

        if (
            pretty_name is None
            and build_id is None
            and ident is None
            and version is None
        ):
            return

        yield "system.distro", DistroVersionData(pretty_name, ident, build_id, version)
