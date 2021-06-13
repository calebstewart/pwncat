#!/usr/bin/env python3

from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule


class ASLRStateData(Fact):
    def __init__(self, source, state):
        super().__init__(source=source, types=["system.aslr"])

        self.state: int = state
        """ the value of /proc/sys/kernel/randomize_va_space """

    def title(self, session):
        if self.state == 0:
            return "[green]disabled[/green]"
        return "[red]enabled[/red]"


class Module(EnumerateModule):
    """
    Determine whether or not ASLR is enabled or disabled.
    :return:
    """

    PROVIDES = ["system.aslr"]
    PLATFORM = [Linux]

    def enumerate(self, session):

        try:
            with session.platform.open(
                "/proc/sys/kernel/randomize_va_space", "r"
            ) as filp:
                value = filp.read()
                try:
                    value = int(value)
                except ValueError:
                    value = None

            if value is not None:
                yield ASLRStateData(self.name, value)
        except (FileNotFoundError, PermissionError):
            pass
