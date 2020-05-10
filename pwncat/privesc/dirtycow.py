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
    BINARIES = ["gcc"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(DirtycowMethod, self).__init__(pty)

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # Test if this kernel version is vulnerable to dirtycow

        return NotImplemented("this function is not yet written")

    def execute(self, technique: Technique):
        """ Run the specified technique """

        # actually perform dirtycow

        return NotImplemented("this function is not yet written")
