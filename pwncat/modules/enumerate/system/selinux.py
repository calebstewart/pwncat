#!/usr/bin/env python3
import dataclasses
from typing import Dict

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class SELinuxState:

    state: str
    status: Dict[str, str]

    def __str__(self):
        result = f"SELinux is "
        if self.state == "enabled":
            result += f"[red]enabled[/red]"
        elif self.state == "disabled":
            result += f"[green]disabled[/green]"
        else:
            result += f"[yellow]{self.state}[/yellow]"
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


class Module(EnumerateModule):
    """
    Retrieve the current SELinux state
    """

    PROVIDES = ["system.selinux"]
    SCHEDULE = Schedule.ONCE
    PLATFORM = [Linux]

    def enumerate(self):

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

        yield "system.selinux", SELinuxState(state, status)
