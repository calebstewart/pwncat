#!/usr/bin/env python3
import dataclasses
from typing import Generator, List, Tuple, Optional

from colorama import Fore

import pwncat
from pwncat import util
from pwncat.enumerate import FactData

name = "pwncat.enumerate.system"
provides = "system.service"
per_user = False


@dataclasses.dataclass
class ServiceData(FactData):

    name: str
    """ The name of the service as given on the remote host """
    uid: int
    """ The user this service is running as """
    state: str
    """ Whether the service is running """
    pid: int

    def __str__(self):
        if self.uid == 0:
            color = "red"
        else:
            color = "green"

        line = f"Service [cyan]{self.name}[/cyan] as [{color}]{pwncat.victim.find_user_by_id(self.uid).name}[/{color}]"
        if self.state == "running":
            color = "green"
        elif self.state == "dead":
            color = "yellow"
        else:
            color = "blue"
        line += f" ([{color}]{self.state}[/{color}])"
        return line


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate the services provided by systemd
    :return:
    """

    try:
        # Look for a enumerator providing the init type
        iter = pwncat.victim.enumerate.iter("system.init")
        fact = next(iter)
        # Make sure to close the iterator
        iter.close()
    except StopIteration:
        # We couldn't  determine the init type
        return

    # We want systemd
    if fact.data.init != util.Init.SYSTEMD:
        return

    # Request the list of services
    # For the generic call, we grab the name, PID, user, and state
    # of each process. If some part of pwncat needs more, it can
    # request it specifically.
    data = pwncat.victim.env(
        [
            "systemctl",
            "show",
            "--type=service",
            "--no-pager",
            "--all",
            "--value",
            "--property",
            "Id",
            "--property",
            "MainPID",
            "--property",
            "UID",
            "--property",
            "SubState",
            "\\*",
        ],
        PAGER="",
    )
    data = data.strip().decode("utf-8").split("\n")

    for i in range(0, len(data), 5):
        if i >= (len(data) - 4):
            break
        name = data[i + 2].strip().rstrip(".service")
        pid = int(data[i].strip())
        if "[not set]" in data[i + 1]:
            uid = 0
        else:
            uid = int(data[i + 1].strip())
        state = data[i + 3].strip()

        yield ServiceData(name, uid, state, pid)
