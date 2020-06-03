#!/usr/bin/env python3
import dataclasses
import shlex
from typing import Generator

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.screen_versions"
provides = "screen-version"
per_user = True


@dataclasses.dataclass
class ScreenVersion(FactData):

    path: str
    perms: int
    vulnerable: bool = True

    def __str__(self):
        return f"{Fore.CYAN}{self.path}{Fore.RESET} (perms: {Fore.BLUE}{oct(self.perms)[2:]}{Fore.RESET})"


def enumerate() -> Generator[FactData, None, None]:
    """
    Find all version of screen that are on the host. This looks for `screen`
    as well as anything like `screen-4.5.0`. This assists with the CVE-2017-5618
    exploit.

    :return:
    """

    # Grab current path plus other interesting paths
    paths = set(pwncat.victim.getenv("PATH").split(":"))
    paths = paths | {
        "/bin",
        "/sbin",
        "/usr/local/bin",
        "/usr/local/sbin",
        "/usr/bin",
        "/usr/sbin",
    }

    # Look for matching binaries
    with pwncat.victim.subprocess(
        f"find {shlex.join(paths)} \( -type f -or -type l \) -executable -name 'screen*' -printf '%#m %p\\n' 2>/dev/null"
    ) as pipe:
        for line in pipe:
            line = line.decode("utf-8").strip()
            perms, *path = line.split(" ")
            path = " ".join(path)
            perms = int(perms, 8)

            yield ScreenVersion(path, perms)
