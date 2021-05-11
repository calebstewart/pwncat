#!/usr/bin/env python3
import pwncat
from pwncat.manager import RawModeExit
from pwncat.commands.base import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """ Return to the remote terminal """

    PROG = "back"
    ARGS = {}

    def run(self, manager: "pwncat.manager.Manager", args):
        raise RawModeExit
