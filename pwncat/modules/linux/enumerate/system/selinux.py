#!/usr/bin/env python3
from typing import Dict

import rich.markup

from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class SELinuxState(Fact):
    def __init__(self, source, state, status):
        super().__init__(source=source, types=["system.selinux"])

        self.state: str = state
        self.status: Dict[str, str] = status

    def title(self, session):
        result = "SELinux is "
        if self.state == "enabled":
            result += "[red]enabled[/red]"
        elif self.state == "disabled":
            result += "[green]disabled[/green]"
        else:
            result += f"[yellow]{rich.markup.escape(self.state)}[/yellow]"
        return result

    @property
    def mode(self) -> str:
        return self.status.get("Current mode", "unknown").lower()

    @property
    def enabled(self) -> bool:
        return self.state.lower() == "enabled"

    def description(self, session):
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

    def enumerate(self, session):

        try:
            output = session.platform.run("sestatus", capture_output=True, text=True)
        except (FileNotFoundError, PermissionError):
            return

        if output:
            output = output.stdout.strip()

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

            yield SELinuxState(self.name, state, status)
