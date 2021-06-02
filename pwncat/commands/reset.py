#!/usr/bin/env python3
import pwncat
from pwncat.commands import CommandDefinition


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

    def run(self, manager: "pwncat.manager.Manager", args):

        manager.log("[yellow]warning[/yellow]: reset not implemented in new framework")
        # pwncat.victim.reset()
