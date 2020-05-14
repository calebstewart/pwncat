#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition, Complete, parameter


class Command(CommandDefinition):
    """ Return to the remote terminal """

    PROG = "back"
    ARGS = {}

    def run(self, args):
        self.pty.enter_raw()
