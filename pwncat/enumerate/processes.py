#!/usr/bin/env python3
import dataclasses
from typing import Generator, List
import shlex

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.processes"
provides = "process"
per_user = False


@dataclasses.dataclass
class ProcessData(FactData):

    uid: int
    pid: int
    ppid: int
    argv: List[str]

    def __str__(self):
        if isinstance(self.uid, str):
            user = self.uid
            color = Fore.YELLOW
        else:
            if self.uid == 0:
                color = Fore.RED
            elif self.uid < 1000:
                color = Fore.BLUE
            else:
                color = Fore.MAGENTA

            # Color our current user differently
            if self.uid == pwncat.victim.current_user.id:
                color = Fore.LIGHTBLUE_EX

            user = self.user.name

        result = f"{color}{user:>10s}{Fore.RESET} "
        result += f"{Fore.MAGENTA}{self.pid:<7d}{Fore.RESET} "
        result += f"{Fore.LIGHTMAGENTA_EX}{self.ppid:<7d}{Fore.RESET} "
        result += f"{Fore.CYAN}{shlex.join(self.argv)}{Fore.RESET}"

        return result

    @property
    def user(self) -> pwncat.db.User:
        return pwncat.victim.find_user_by_id(self.uid)


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate all running processes. Extract command line, user, and pts information
    :return:
    """

    ps = pwncat.victim.which("ps")

    if ps is not None:
        with pwncat.victim.subprocess(
            f"{ps} -eo pid,ppid,user,command --no-header -ww", "r"
        ) as filp:
            # Skip first line... it's just the headers
            try:
                # next(filp)
                pass
            except StopIteration:
                pass

            # Iterate over each process
            for line in filp:
                line = line.strip().decode("utf-8")

                entities = line.split()
                pid, ppid, username, *argv = entities
                if username not in pwncat.victim.users:
                    uid = username
                else:
                    uid = pwncat.victim.users[username].id

                command = " ".join(argv)
                # Kernel threads aren't helpful for us
                if command.startswith("[") and command.endswith("]"):
                    continue

                pid = int(pid)
                ppid = int(ppid)

                yield ProcessData(uid, pid, ppid, argv)
    else:
        # We should try to parse /proc. It's slow, but should work.
        # I'll implement that later.
        pass
