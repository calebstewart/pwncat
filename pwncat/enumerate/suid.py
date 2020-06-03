#!/usr/bin/env python3
import dataclasses
import os
from typing import Generator

from colorama import Fore

import pwncat
from pwncat import util

name = "pwncat.enumerate.suid"
provides = "suid"
per_user = True


@dataclasses.dataclass
class Binary:
    """
    A generic description of a SUID binary
    """

    path: str
    """ The path to the binary """
    uid: int
    """ The owner of the binary """

    def __str__(self):
        color = Fore.RED if self.owner.id == 0 else Fore.GREEN
        return f"{Fore.CYAN}{self.path}{Fore.RESET} owned by {color}{self.owner.name}{Fore.RESET}"

    @property
    def owner(self):
        return pwncat.victim.find_user_by_id(self.uid)


def enumerate() -> Generator[Binary, None, None]:
    """
    Enumerate all new Set UID binaries. These are turned into facts by pwncat.victim.enumerate
    which can be generically retrieved with pwncat.victim.enumerate.iter("suid"). This also
    inserts a dummy-fact named "suid-searched-{uid}" to indicate we have already searched for
    SUID binaries as a given user.
 
    :return: Generator[Binary, None, None]
    """

    # Spawn a find command to locate the setuid binaries
    with pwncat.victim.subprocess(
        "find / -perm -4000 -printf '%U %p\\n' 2>/dev/null", mode="r", no_job=True
    ) as stream:
        for path in stream:
            # Parse out owner ID and path
            path = path.strip().decode("utf-8").split(" ")
            uid, path = int(path[0]), " ".join(path[1:])

            # Check if we already know about this SUID binary from a different search
            # This will only searched the cached database entries and not end up being
            # recursive.
            try:
                next(
                    pwncat.victim.enumerate.iter(
                        "suid", only_cached=True, filter=lambda f: f.data.path == path,
                    )
                )
            except StopIteration:
                pass
            else:
                continue

            yield Binary(path, uid)
