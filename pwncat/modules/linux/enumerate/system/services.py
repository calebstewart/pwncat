#!/usr/bin/env python3
import subprocess

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.util import Init
from pwncat.modules import Status, ModuleFailed
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule

"""
TODO: This is weirdly inconsistent. Sometimes it works, other times it misses
like more than half of the services. We don't know why. systemctl might be
doing something weird?
"""


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


def build_service_data(session, source, service):
    """ Build a service data object from a dictionary """

    # Grab the user name if available
    user = service.get("User", None).strip()

    # Resolve to user object
    if user is not None:
        user = session.find_user(name=user)

    # If the user existed, grab the ID
    if user is not None:
        uid = user.id
    else:
        # Otherwise, assume it was root
        uid = 0

    try:
        pid = int(service.get("MainPID", None))
    except ValueError:
        pid = None

    return ServiceData(
        source=source,
        name=service["Id"].strip(),
        uid=uid,
        state=service.get("SubState", "unknown").strip(),
        pid=pid,
    )


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

        # Ensure we build the user cache
        session.find_user(uid=0)

        try:
            # List all services and grab the details
            proc = session.platform.Popen(
                "systemctl list-units --type=service --no-pager --all --no-legend --plain | cut -d' ' -f1 | xargs systemctl show --no-pager --all --property Id --property User --property MainPID --property SubState",
                shell=True,
                stdout=subprocess.PIPE,
                text=True,
            )

            service = {}

            for line in proc.stdout:
                if line.strip() == "":
                    # We can only build a service structure if we know the name
                    if "Id" in service and service["Id"].strip() != "":
                        yield build_service_data(session, self.name, service)

                    # Reset service dict
                    service = {}
                    continue

                # Store the key-value pair in the dict
                name, *value = line.split("=")
                value = "=".join(value)
                service[name] = value

        finally:
            try:
                proc.wait(2)
            except TimeoutError:
                proc.kill()
                proc.wait()
