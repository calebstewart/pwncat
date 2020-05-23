#!/usr/bin/env python3
import sys

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, parameter


class Command(CommandDefinition):
    """
    Run a shell command on the victim host and display the output.
    
    **NOTE** This must be a non-interactive command. If an interactive command
        is run, you will have to use C-c to return to the pwncat prompt and then
        C-d to get back to your interactive remote prompt in order to interact
        with the remote host again!"""

    PROG = "run"
    ARGS = None

    def run(self, args):
        sys.stdout.buffer.write(pwncat.victim.run(args))
