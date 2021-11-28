#!/usr/bin/env python3
import pwncat
from pwncat.commands import CommandDefinition


class Command(CommandDefinition):
    """
    Return to the remote terminal
    """

    PROG = "back"
    ARGS = {}

    def run(self, manager: "pwncat.manager.Manager", args):
        # This is caught by ``CommandParser.run`` which interprets
        # it as a `C-d` sequence, and returns to the remote prompt.
        raise EOFError
