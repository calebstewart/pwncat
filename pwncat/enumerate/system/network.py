#!/usr/bin/env python3
import dataclasses
from typing import Generator

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.system"
provides = "system.network"
per_user = False


@dataclasses.dataclass
class NetworkData(FactData):

    interface: str
    address: str

    def __str__(self):
        return f"Interface {Fore.CYAN}{self.interface}{Fore.RESET} w/ address {Fore.BLUE}{self.address}{Fore.RESET}"


def enumerate() -> Generator[FactData, None, None]:

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
                yield NetworkData(interface, address)

        return
    except FileNotFoundError:
        pass

    # We really should try ifconfig if `ip` fails...
