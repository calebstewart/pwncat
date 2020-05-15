#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat import util


class Command(CommandDefinition):
    """ Return to the remote terminal """

    PROG = "back"
    ARGS = {}

    def run(self, args):
        self.pty.state = util.State.RAW
