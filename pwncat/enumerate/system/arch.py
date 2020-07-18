#!/usr/bin/env python3
import dataclasses
from typing import Generator, List

from colorama import Fore

from pwncat.enumerate import FactData
from pwncat import util
import pwncat

name = "pwncat.enumerate.system"
provides = "system.arch"
per_user = False


@dataclasses.dataclass
class ArchData(FactData):
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.

    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    arch: str

    def __str__(self):
        return f"Running on a [cyan]{self.arch}[/cyan] processor"


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate kernel/OS version information
    :return:
    """

    try:
        result = pwncat.victim.env(["uname", "-m"]).decode("utf-8").strip()
    except FileNotFoundError:
        return

    yield ArchData(result)
