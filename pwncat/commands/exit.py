#!/usr/bin/env python3
import pwncat
from pwncat.util import console
from pwncat.commands.base import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Exit the interactive prompt. If sessions are active, you will
    be prompted to confirm. This shouldn't be run from a configuration
    script.
    """

    PROG = "exit"
    ARGS = {}
    LOCAL = True

    def run(self, manager, args):
        raise pwncat.manager.InteractiveExit
