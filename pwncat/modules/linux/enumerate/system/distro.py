#!/usr/bin/env python3
import dataclasses
from typing import List

import pwncat
import rich.markup
from pwncat import util
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class DistroVersionData(Fact):
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.

    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    def __init__(self, source, name, ident, build_id, version):
        super().__init__(source=source, types=["system.distro"])

        self.name: str = name
        self.ident: str = ident
        self.build_id: str = build_id
        self.version: str = version

    def title(self, session):
        return (
            f"[blue]{rich.markup.escape(str(self.name))}[/blue] ([cyan]{rich.markup.escape(self.ident)}[/cyan]), "
            f"Version [red]{rich.markup.escape(str(self.version))}[/red], "
            f"Build ID [green]{rich.markup.escape(str(self.build_id))}[/green]."
        )


class Module(EnumerateModule):
    """
    Enumerate OS/Distribution version information
    """

    PROVIDES = ["system.distro"]
    PLATFORM = [Linux]

    def enumerate(self, session):

        build_id = None
        pretty_name = None
        ident = None
        version = None

        try:
            with session.platform.open("/etc/os-release", "r") as filp:
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
                with session.platform.open("/etc/lsb-release", "r") as filp:
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

        yield DistroVersionData(self.name, pretty_name, ident, build_id, version)
