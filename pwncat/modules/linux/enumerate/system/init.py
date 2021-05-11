#!/usr/bin/env python3
from typing import List
import dataclasses

import rich.markup

import pwncat
from pwncat import util
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule, Schedule


class InitSystemData(Fact):
    def __init__(self, source, init, version):
        super().__init__(source=source, types=["system.init"])

        self.init: util.Init = init
        self.version: str = version

    def title(self, session):
        return f"Running [blue]{self.init}[/blue]"


class Module(EnumerateModule):
    """
    Enumerate system init service
    :return:
    """

    PROVIDES = ["system.init"]
    PLATFORM = [Linux]

    def enumerate(self, session):

        init = util.Init.UNKNOWN
        version = None

        # Try to get the command name of the running init process
        try:
            with session.platform.open("/proc/1/comm", "r") as filp:
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
            with session.platform.open("/proc/1/cmdline", "r") as filp:
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

        proc = session.platform.run(f"{comm} --version", capture_output=True, text=True)
        version = ""
        if proc.stdout:
            version = proc.stdout.strip()
            if "systemd" in version.lower():
                init = util.Init.SYSTEMD
            elif "sysv" in version.lower():
                init = util.Init.SYSV
            elif "upstart" in version.lower():
                init = util.Init.UPSTART

        # No need to provide an empty version string. They apparently don't support "--version"
        if version == "":
            version = None

        yield InitSystemData(self.name, init, version)
