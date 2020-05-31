#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition
import pwncat


class Command(CommandDefinition):
    """
    Reset the remote terminal to the standard pwncat settings. This will set
    your remote prompt and synchronize the terminal state. It will also ensure
    that the HISTFILE, PROMPT_COMMAND, and other common shell settings are setup
    properly. Run this if you ever end up in a peculiar situation on the remote
    host and are unable to reset it manually.
    """

    PROG = "reset"
    ARGS = {}
    DEFAULTS = {}
    LOCAL = False

    def run(self, args):
        pwncat.victim.reset()
