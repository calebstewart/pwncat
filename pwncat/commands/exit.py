#!/usr/bin/env python3
from pwncat.util import console
from pwncat.commands.base import CommandDefinition, Complete, Parameter


class Command(CommandDefinition):
    """
    Exit pwncat. You must provide the "--yes" parameter.
    This prevents accidental closing of your remote session.
    """

    PROG = "exit"
    ARGS = {
        "--yes,-y": Parameter(
            Complete.NONE,
            action="store_true",
            help="Confirm you would like to close pwncat",
        )
    }
    LOCAL = True

    def run(self, args):

        # Ensure we confirmed we want to exit
        if not args.yes:
            console.log("[red]error[/red]: exit not confirmed (use '--yes')")
            return

        # Get outa here!
        raise EOFError
