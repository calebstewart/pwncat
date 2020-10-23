#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform.linux import Linux
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class ASLRStateData:

    state: int
    """ the value of /proc/sys/kernel/randomize_va_space """

    def __str__(self):
        if self.state == 0:
            return f"ASLR is [green]disabled[/green]"
        return f"ASLR is [red]enabled[/red]"


class Module(EnumerateModule):
    """
    Determine whether or not ASLR is enabled or disabled.
    :return:
    """

    PROVIDES = ["system.aslr"]
    PLATFORM = [Linux]

    def enumerate(self):

        try:
            with pwncat.victim.open("/proc/sys/kernel/randomize_va_space", "r") as filp:
                value = filp.read()
                try:
                    value = int(value)
                except ValueError:
                    value = None

            if value is not None:
                yield "system.aslr", ASLRStateData(value)
        except (FileNotFoundError, PermissionError):
            pass
