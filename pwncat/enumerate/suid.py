#!/usr/bin/env python3
import dataclasses
import os
from typing import Generator

from colorama import Fore

import pwncat
from pwncat import util

name = "pwncat.enumerate.suid"
provides = "suid"


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
        return f"{Fore.YELLOW}{self.path}{Fore.RESET} owned by {Fore.GREEN}{self.owner.name}{Fore.RESET}"

    @property
    def description(self) -> str:
        return str(self)

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

    current_user = pwncat.victim.current_user

    # We've already enumerated this user
    if pwncat.victim.enumerate.exist(
        f"suid", provider=f"suid-searched-{current_user.id}"
    ):
        return

    # Add the fact indicating we already searched for SUID binaries
    pwncat.victim.enumerate.add_fact(f"suid", None, f"suid-searched-{current_user.id}")

    # Spawn a find command to locate the setuid binaries
    with pwncat.victim.subprocess(
        "find / -perm -4000 -printf '%U %p\\n' 2>/dev/null", mode="r", no_job=True
    ) as stream:
        util.progress("searching for setuid binaries")
        for path in stream:
            # Parse out owner ID and path
            path = path.strip().decode("utf-8").split(" ")
            uid, path = int(path[0]), " ".join(path[1:])

            # Print status message
            util.progress(
                (
                    f"searching for setuid binaries as {Fore.GREEN}{current_user.name}{Fore.RESET}: "
                    f"{Fore.CYAN}{os.path.basename(path)}{Fore.RESET}"
                )
            )

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
