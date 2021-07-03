#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class InterfaceData(Fact):
    def __init__(self, source, interface, address):
        super().__init__(source=source, types=["system.network.interface"])

        self.interface: str = interface
        self.address: str = address

    def title(self, session):
        return f"Interface [cyan]{rich.markup.escape(self.interface)}[/cyan] w/ address [blue]{rich.markup.escape(self.address)}[/blue]"


class Module(EnumerateModule):
    """
    Enumerate network interfaces with active connections
    and return their name and IP address.
    """

    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE
    PROVIDES = ["system.network.interface"]

    def enumerate(self, session):

        try:
            output = session.platform.run(
                ["ip", "-c=never", "addr"], capture_output=True, text=True, check=True
            )
        except CalledProcessError:
            try:
                output = session.platform.run(
                    ["ip", "addr"], capture_output=True, text=True, check=True
                )
            except CalledProcessError:
                return
        except FileNotFoundError:
            return

        if output.stdout:
            output = (
                line for line in output.stdout.replace("\r\n", "\n").split("\n") if line
            )

            interface = None

            for line in output:
                if not line.startswith(" "):
                    interface = line.split(":")[1].strip()
                    continue

                if interface is None:
                    # This shouldn't happen. The first line should be an interface
                    # definition, but just in case
                    continue

                line = line.strip()
                if line.startswith("inet"):
                    address = line.split(" ")[1]
                    yield InterfaceData(self.name, interface, address)
