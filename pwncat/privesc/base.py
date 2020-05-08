#!/usr/bin/env python3
from typing import Generator, Callable
import threading
import socket
import os

from pwncat import util


class PrivescError(Exception):
    """ An error occurred while attempting a privesc technique """


class Privesc:

    # Binaries which are needed on the remote host for this privesc
    BINARIES = []

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Check if the given PTY connection can support this privesc """
        for binary in cls.BINARIES:
            if pty.which(binary) is None:
                raise DownloadError(f"required remote binary not found: {binary}")

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        self.pty = pty

    def execute(self) -> Generator[str, None, None]:
        """ Generate the commands needed to send this file back. This is a 
            generator, which yields strings which will be executed on the remote
            host. """
        return
