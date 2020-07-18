#!/usr/bin/env python3
import dataclasses
from typing import Generator

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.system"
provides = "system.aslr"
per_user = False


@dataclasses.dataclass
class ASLRState(FactData):

    state: int
    """ the value of /proc/sys/kernel/randomize_va_space """

    def __str__(self):
        if self.state == 0:
            return f"ASLR is [green]disabled[/green]"
        return f"ASLR is [red]enabled[/red]"


def enumerate() -> Generator[FactData, None, None]:
    """
    Check if this system is inside a container
    :return:
    """

    try:
        with pwncat.victim.open("/proc/sys/kernel/randomize_va_space", "r") as filp:
            value = filp.read()
            try:
                value = int(value)
            except ValueError:
                value = None

        if value is not None:
            yield ASLRState(value)
    except (FileNotFoundError, PermissionError):
        pass
