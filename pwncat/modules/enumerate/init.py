#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform import Platform
from pwncat import util
from pwncat.modules import Result
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class InitSystemData(Result):

    init: util.Init
    version: str

    @property
    def title(self):
        return f"Running [blue]{self.init}[/blue]"


class Module(EnumerateModule):
    """
    Enumerate system init service
    :return:
    """

    PROVIDES = ["system.init"]
    PLATFORM = Platform.LINUX

    def enumerate(self):

        init = util.Init.UNKNOWN
        version = None

        # Try to get the command name of the running init process
        try:
            with pwncat.victim.open("/proc/1/comm", "r") as filp:
                comm = filp.read().strip()
            if comm is not None:
                if "systemd" in comm.lower():
                    init = util.Init.SYSTEMD
                elif "sysv" in comm.lower():
                    init = util.Init.SYSV
                elif "upstart" in comm.lower():
                    init = util.Init.UPSTART
        except (PermissionError, FileNotFoundError):
            comm = None

        # Try to get the command name of the running init process
        try:
            with pwncat.victim.open("/proc/1/cmdline", "r") as filp:
                comm = filp.read().strip().split("\x00")[0]
        except (PermissionError, FileNotFoundError):
            comm = None

        if comm is not None:
            if "systemd" in comm.lower():
                init = util.Init.SYSTEMD
            elif "sysv" in comm.lower():
                init = util.Init.SYSV
            elif "upstart" in comm.lower():
                init = util.Init.UPSTART

        with pwncat.victim.subprocess(f"{comm} --version", "r") as filp:
            version = filp.read().decode("utf-8").strip()
        if "systemd" in version.lower():
            init = util.Init.SYSTEMD
        elif "sysv" in version.lower():
            init = util.Init.SYSV
        elif "upstart" in version.lower():
            init = util.Init.UPSTART

        # No need to provide an empty version string. They apparently don't support "--version"
        if version == "":
            version = None

        yield "system.init", InitSystemData(init, version)
