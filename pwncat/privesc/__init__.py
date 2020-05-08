#!/usr/bin/env python3
from typing import Type, List

from pwncat.privesc.base import Method, PrivescError, Technique, SuMethod
from pwncat.privesc.setuid import SetuidMethod

methods = [SetuidMethod]


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
        for m in [SetuidMethod, SuMethod]:
            try:
                m.check(self.pty)
                self.methods.append(m())
            except PrivescError:
                pass

    def escalate(
        self,
        target_user: str = None,
        depth: int = None,
        chain: List[Technique] = [],
        starting_user=None,
    ):
        """ Search for a technique chain which will gain access as the given 
        user. """

        current_user = self.pty.current_user
        if (
            target_user == current_user["name"]
            or current_user["id"] == 0
            or current_user["name"] == "root"
        ):
            raise PrivescError(f"you are already {current_user['name']}")

        if starting_user is None:
            starting_user = current_user

        if len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            techniques.extend(method.enumerate())

        # Escalate directly to the target
        for tech in techniques:
            if tech.user == target_user:
                try:
                    tech.method.execute(tech)
                    chain.append(tech)
                    return chain
                except PrivescError:
                    pass

        # We can't escalate directly to the target. Instead, try recursively
        # against other users.
        for tech in techniques:
            if tech.user == target_user:
                continue
            try:
                tech.method.execute(tech)
                chain.append(tech)
            except PrivescError:
                continue
            try:
                return self.escalate(target_user, depth, chain, starting_user)
            except PrivescError:
                self.pty.run("exit", wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")
