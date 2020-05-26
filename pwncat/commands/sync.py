#!/usr/bin/env python3
import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat import util
import os


class Command(CommandDefinition):
    """ Synchronize the remote terminal with the local terminal. This will
    attempt to set the remote prompt, terminal width, terminal height, and TERM
    environment variables to enable to cleanest interface to the remote system
    possible. """

    PROG = "sync"
    ARGS = {}
    DEFAULTS = {}

    def run(self, args):

        # Get the terminal type
        TERM = os.environ.get("TERM", None)
        if TERM is None:
            util.warn("no local TERM set. falling back to 'xterm'")
            TERM = "xterm"

        # Get the width and height
        columns, rows = os.get_terminal_size(0)

        # Update the state
        pwncat.victim.run(
            f"stty rows {rows};" f"stty columns {columns};" f"export TERM='{TERM}'"
        )

        util.success("terminal state synchronized")
