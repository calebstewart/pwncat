#!/usr/bin/env python3

from typing import Optional

import rich.markup

from pwncat.db import Fact
from pwncat.modules import Status, ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Scope, Schedule, EnumerateModule


class ProcessData(Fact):
    """Remote process information"""

    def __init__(
        self,
        source: str,
        name: str,
        pid: int,
        session: Optional[int],
        owner: str,
        state: int,
        path: str,
        commandline: str,
        handle: int,
    ):
        super().__init__(source=source, types=["system.processes"])

        self.name: str = name
        self.pid: int = pid
        self.session: int = session
        self.owner: str = owner
        self.state: int = state
        self.path: str = path
        self.commandline: str = commandline
        self.handle: int = handle

        if self.path == "":
            self.path = None
        if self.owner == "":
            self.owner = None

    def kill(self, session):
        """Attempt to kill the process"""

        try:
            session.platform.powershell(f"(Get-Process -Id {self.pid}).Kill()")
        except PowershellError as exc:
            raise ModuleFailed(f"failed to kill process {self.pid}") from exc

    def wait(self, session, timeout: int = -1):
        """
        Wait for the process to exit.

        :param timeout: The amount of time , in milliseconds, to wait for the associated process to exit.
            0 specifies an immediate exit. -1 specifies an infinite wait.
        :type timeout: int
        :raises:
            TimeoutError: the process did not exit within the timeout specified
            PermissionError: you do not have permission to wait for the specified process or the process does not exist
        """

        try:
            result = session.platform.powershell(
                f"(Get-Process -Id {self.pid}).WaitForExit({timeout})"
            )
            if not result or not result[0]:
                raise TimeoutError(self)
        except PowershellError:
            raise PermissionError(f"cannot wait for process w/ pid {self.pid}")

    def title(self, session):
        """Build a formatted description for this process"""

        out = "[cyan]{name}[/cyan] (PID [blue]{pid}[/blue]) is {state} "

        state = "[green]running[/green]"
        if self.state == 7:
            state = "[red]terminated[/red]"
        elif self.state == 8:
            state = "[yellow]stopped[/red]"

        if self.owner is None:
            color = "yellow"
            owner = "unknown"
        else:
            color = "magenta"

            owner = session.find_user(uid=self.owner)
            if owner is None:
                owner = session.find_group(gid=self.owner)
            if owner is None:
                owner = f"SID({repr(self.owner)})"
            else:
                owner = owner.name

        out += "owned by [{color}]{owner}[/{color}]"

        return out.format(
            name=rich.markup.escape(self.name),
            pid=self.pid,
            owner=owner,
            color=color,
            state=state,
        )


class Module(EnumerateModule):
    """Retrieve a list of current processes running on the target"""

    PROVIDES = ["system.processes"]
    PLATFORM = [Windows]
    # We don't save process results. They're volatile. Maybe this should be `Schedule.ALWAYS` anyway though? :shrug:
    SCHEDULE = Schedule.ALWAYS
    SCOPE = Scope.NONE

    def enumerate(self, session):

        script = """
Get-WmiObject -Class Win32_Process | % {
    [PSCustomObject]@{
        commandline=$_.CommandLine;
        description=$_.Description;
        path=$_.ExecutablePath;
        state=$_.ExecutionState;
        handle=$_.Handle;
        name=$_.Name;
        id=$_.ProcessId;
        session=$_.SessionId;
        owner=$_.GetOwnerSid().Sid;
    }
}
        """

        try:
            yield Status("requesting process list...")
            processes = session.platform.powershell(script)[0]
        except (IndexError, PowershellError) as exc:
            raise ModuleFailed(f"failed to get running processes: {exc}")

        for proc in processes:
            yield ProcessData(
                source=self.name,
                name=proc["name"],
                pid=proc["id"],
                session=proc.get("session"),
                owner=proc["owner"],
                state=proc["state"],
                commandline=proc["commandline"],
                path=proc["path"],
                handle=proc["handle"],
            )
