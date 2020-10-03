#!/usr/bin/env python3
import dataclasses

from pwncat.modules.enumerate import EnumerateModule, Schedule
import pwncat
from pwncat.platform import Platform
from pwncat.util import Init


@dataclasses.dataclass
class ServiceData:

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

        try:
            user_name = pwncat.victim.find_user_by_id(self.uid).name
        except KeyError:
            user_name = f"{self.uid} (unknown user)"
            color = "yellow"

        line = f"Service [cyan]{self.name}[/cyan] as [{color}]{user_name}[/{color}]"
        if self.state == "running":
            color = "green"
        elif self.state == "dead":
            color = "yellow"
        else:
            color = "blue"
        line += f" ([{color}]{self.state}[/{color}])"
        return line


class Module(EnumerateModule):
    """ Enumerate systemd services on the victim """

    PROVIDES = ["system.service"]
    PLATFORM = Platform.LINUX
    SCHEDULE = Schedule.ONCE

    def enumerate(self):

        for fact in pwncat.modules.run(
            "enumerate.gather", types=["system.init"], progress=self.progress
        ):
            if fact.data.init != Init.SYSTEMD:
                return
            break

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

            yield "system.service", ServiceData(name, uid, state, pid)
