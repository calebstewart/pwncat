#!/usr/bin/env python3

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.util import Init
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class ServiceData(Fact):
    def __init__(self, source, name, uid, state, pid):
        super().__init__(source=source, types=["system.service"])

        self.name: str = name
        """ The name of the service as given on the remote host """
        self.uid: int = uid
        """ The user this service is running as """
        self.state: str = state
        """ Whether the service is running """
        self.pid: int = pid

    def title(self, session):
        if self.uid == 0:
            color = "red"
        else:
            color = "green"

        try:
            user_name = session.find_user(uid=self.uid).name
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
    """Enumerate systemd services on the victim"""

    PROVIDES = ["system.service"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):

        for fact in session.run(
            "enumerate.gather", types=["system.init"], progress=self.progress
        ):
            if fact.init != Init.SYSTEMD:
                return
            break

        # Request the list of services
        # For the generic call, we grab the name, PID, user, and state
        # of each process. If some part of pwncat needs more, it can
        # request it specifically.

        data = session.platform.run(
            "systemctl show --type=service --no-pager --all --value --property Id --property MainPID --property UID --property SubState \\*",
            capture_output=True,
            text=True,
            check=True,
        )

        if data.stdout:
            data = data.stdout.split("\n\n")

            for segment in data:
                section = segment.split("\n")
                try:
                    pid = int(section[0])
                except ValueError as exc:
                    pwncat.console.log(repr(data), markup=False)
                if section[1] == "[not set]":
                    uid = 0
                else:
                    uid = int(section[1])
                name = section[2].removesuffix(".service")
                state = section[3]

                yield ServiceData(self.name, name, uid, state, pid)
