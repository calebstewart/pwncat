#!/usr/bin/env python3
from pwncat import util
from pwncat.commands.base import CommandDefinition, Complete, parameter


class Command(CommandDefinition):
    """
    Exit pwncat. You must provide the "--yes" parameter.
    This prevents accidental closing of your remote session.
    """

    PROG = "exit"
    ARGS = {
        "--yes,-y": parameter(
            Complete.NONE,
            action="store_true",
            help="Confirm you would like to close pwncat",
        )
    }
    LOCAL = True

    def run(self, args):

        # Ensure we confirmed we want to exit
        if not args.yes:
            util.error("exit not confirmed")
            return

        # Get outa here!
        raise EOFError
