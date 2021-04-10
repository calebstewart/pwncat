#!/usr/bin/env python3
import dataclasses

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class InterfaceData:

    interface: str
    address: str

    def __str__(self):
        return f"Interface [cyan]{self.interface}[/cyan] w/ address [blue]{self.address}[/blue]"


class Module(EnumerateModule):
    """
    Enumerate network interfaces with active connections
    and return their name and IP address.
    """

    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE
    PROVIDES = ["system.network.interface"]

    def enumerate(self):

        try:
            output = pwncat.victim.env(["ip", "addr"]).decode("utf-8").strip()
            output = output.replace("\r\n", "\n").split("\n")
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
                    yield "system.network.interface", InterfaceData(interface, address)

            return
        except FileNotFoundError:
            pass
