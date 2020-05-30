#!/usr/bin/env python3
import dataclasses
import os
import re
from datetime import datetime
from typing import Generator, Tuple

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.crontab"
provides = "system.crontab"
per_user = True
always_run = False


@dataclasses.dataclass
class CronEntry(FactData):

    path: str
    """ The path to the crontab where this was found """
    uid: int
    """ The user ID this entry will run as """
    command: str
    """ The command that will execute """
    datetime: str
    """ The entire date/time specifier from the crontab entry """

    def __str__(self):
        return f"{Fore.BLUE}{self.user.name}{Fore.RESET} runs {Fore.YELLOW}{repr(self.command)}{Fore.RESET}"

    @property
    def description(self):
        return f"{self.path}: {self.datetime} {self.command}"

    @property
    def user(self):
        return pwncat.victim.find_user_by_id(self.uid)


def parse_crontab(path: str, line: str, system: bool = True) -> CronEntry:
    """
    Parse a crontab line. This returns a tuple of (command, datetime, user) indicating
    the command to run, when it will execute, and who it will execute as. If system is
    false, then the current user is returned and no user element is parsed (assumed
    not present).

    This will raise a ValueError if the line is malformed.

    :param line: the line from crontab
    :param system: whether this is a system or user crontab entry
    :return: a tuple of (command, datetime, username)
    """

    # Variable assignment, comment or empty line
    if (
        line.startswith("#")
        or line == ""
        or re.match(r"[a-zA-Z][a-zA-Z0-9_-]*\s*=.*", line) is not None
    ):
        raise ValueError

    entry = [x for x in line.strip().replace("\t", " ").split(" ") if x != ""]

    # Malformed entry or comment
    if (len(entry) <= 5 and not system) or (len(entry) <= 6 and system):
        raise ValueError

    when = " ".join(entry[:5])

    if system:
        uid = pwncat.victim.users[entry[5]].id
        command = " ".join(entry[6:])
    else:
        uid = pwncat.victim.current_user.id
        command = " ".join(entry[5:])

    return CronEntry(path, uid, command, when)


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate system and/or user crontab entries.

    :return:
    """

    try:
        user_entries = pwncat.victim.env(["crontab", "-l"]).decode("utf-8")
    except FileNotFoundError:
        # The crontab command doesn't exist :(
        return

    for line in user_entries.split("\n"):
        try:
            yield parse_crontab("crontab -l", line, system=False)
        except ValueError:
            continue

    known_tabs = ["/etc/crontab"]

    for tab_path in known_tabs:
        try:
            with pwncat.victim.open(tab_path, "r") as filp:
                for line in filp:
                    try:
                        yield parse_crontab(tab_path, line, system=True)
                    except ValueError:
                        continue
        except (FileNotFoundError, PermissionError):
            pass

    known_dirs = [
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ]
    for dir_path in known_dirs:
        try:
            filenames = list(pwncat.victim.listdir(dir_path))
            for filename in filenames:
                if filename == "." or filename == "..":
                    continue
                try:
                    with pwncat.victim.open(
                        os.path.join(dir_path, filename), "r"
                    ) as filp:
                        for line in filp:
                            try:
                                yield parse_crontab(
                                    os.path.join(dir_path, filename), line, system=True
                                )
                            except ValueError:
                                pass
                except (FileNotFoundError, PermissionError):
                    pass
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            pass
