#!/usr/bin/env python3
import dataclasses
from typing import Generator, List

from colorama import Fore

from pwncat.enumerate import FactData
from pwncat import util
import pwncat

name = "pwncat.enumerate.system"
provides = "system.init"
per_user = False


@dataclasses.dataclass
class InitSystemData(FactData):

    init: util.Init
    version: str

    def __str__(self):
        return f"Running {Fore.BLUE}{self.init}{Fore.RESET}"

    @property
    def description(self):
        return self.version


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate system init service
    :return:
    """

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

    yield InitSystemData(init, version)
