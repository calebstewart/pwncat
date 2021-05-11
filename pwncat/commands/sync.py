#!/usr/bin/env python3
import os

import pwncat
from pwncat.util import console
from pwncat.commands.base import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """Synchronize the remote terminal with the local terminal. This will
    attempt to set the remote prompt, terminal width, terminal height, and TERM
    environment variables to enable to cleanest interface to the remote system
    possible."""

    PROG = "sync"
    ARGS = {
        "--quiet,-q": Parameter(
            Complete.NONE, action="store_true", help="do not output status messages"
        )
    }
    DEFAULTS = {}

    def run(self, args):

        manager.log("[red]error[/red]: sync not implemented in new framework (yet)")
        return

        # Get the terminal type
        TERM = os.environ.get("TERM", None)
        if TERM is None:
            if not args.quiet:
                console.log(
                    "[yellow]warning[/yellow]: no local [blue]TERM[/blue]; falling back to 'xterm'"
                )
            TERM = "xterm"

        # Get the width and height
        columns, rows = os.get_terminal_size(0)

        # Update the state
        pwncat.victim.run(
            f"stty rows {rows}; stty columns {columns}; export TERM='{TERM}'"
        )

        if not args.quiet:
            console.log(
                "[green]:heavy_check_mark:[/green] terminal state synchronized",
                emoji=True,
            )
