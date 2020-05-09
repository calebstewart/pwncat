#!/usr/bin/env python3
from typing import Generator, Callable, List, Any
from dataclasses import dataclass
from colorama import Fore
import threading
import socket
import os

from pwncat import util


class ReaderError(Exception):
    """ An error occurred while attempting a privesc technique """


@dataclass
class Technique:
    # The user that this technique will move to
    filename: str
    # The method that will be used
    method: "Method"
    # The unique identifier for this method (can be anything, specific to the
    # method)
    ident: Any

    def __str__(self):
        return self.method.get_name(self)


class Method:

    # Binaries which are needed on the remote host for this file read functionality
    name = "unknown"
    BINARIES = []

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Check if the given PTY connection can support this privesc """
        for binary in cls.BINARIES:
            if pty.which(binary) is None:
                raise ReaderError(f"required remote binary not found: {binary}")

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        self.pty = pty

    def enumerate(self) -> List[Technique]:
        """ Enumerate all possible escalations to the given users """
        raise NotImplementedError("no enumerate method implemented")

    def execute(self, technique: Technique):
        """ Execute the given technique to move laterally to the given user. 
        Raise a PrivescError if there was a problem. """
        raise NotImplementedError("no execute method implemented")

    def get_name(self, tech: Technique):
        return f"{Fore.GREEN}{tech.filename}{Fore.RESET} via {Fore.RED}{self}{Fore.RED}"

    def __str__(self):
        return self.name
