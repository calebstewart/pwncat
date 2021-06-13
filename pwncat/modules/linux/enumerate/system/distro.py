#!/usr/bin/env python3


from pwncat.facts import DistroVersionData
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule


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
