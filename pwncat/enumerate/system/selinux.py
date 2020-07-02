#!/usr/bin/env python3
import dataclasses
from typing import Generator, Dict

from colorama import Fore

from pwncat.enumerate import FactData
import pwncat

name = "pwncat.enumerate.system"
provides = "system.selinux"
per_user = False


@dataclasses.dataclass
class SELinuxState(FactData):

    state: str
    status: Dict[str, str]

    def __str__(self):
        result = f"SELinux is "
        if self.state == "enabled":
            result += f"{Fore.RED}enabled{Fore.RESET}"
        elif self.state == "disabled":
            result += f"{Fore.GREEN}disabled{Fore.RESET}"
        else:
            result += f"{Fore.YELLOW}{self.state}{Fore.RESET}"
        return result

    @property
    def mode(self) -> str:
        return self.status.get("Current mode", "unknown").lower()

    @property
    def enabled(self) -> bool:
        return self.state.lower() == "enabled"

    @property
    def description(self):
        width = max(len(x) for x in self.status) + 1
        return "\n".join(
            f"{key+':':{width}} {value}" for key, value in self.status.items()
        )


def enumerate() -> Generator[FactData, None, None]:
    """
    Check for SELinux status/availability
    """

    try:
        output = pwncat.victim.env(["sestatus"]).strip().decode("utf-8")
    except (FileNotFoundError, PermissionError):
        return

    status = {}
    for line in output.split("\n"):
        line = line.strip().replace("\t", " ")
        values = " ".join([x for x in line.split(" ") if x != ""]).split(":")
        key = values[0].rstrip(":").strip()
        value = " ".join(values[1:])
        status[key] = value.strip()

    if "SELinux status" in status:
        state = status["SELinux status"]
    else:
        state = "unknown"

    yield SELinuxState(state, status)
