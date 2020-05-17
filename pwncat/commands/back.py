#!/usr/bin/env python3
import pwncat
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat import util


class Command(CommandDefinition):
    """ Return to the remote terminal """

    PROG = "back"
    ARGS = {}

    def run(self, args):
        pwncat.victim.state = util.State.RAW
