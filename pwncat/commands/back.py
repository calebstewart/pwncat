#!/usr/bin/env python3
import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.manager import RawModeExit


class Command(CommandDefinition):
    """ Return to the remote terminal """

    PROG = "back"
    ARGS = {}

    def run(self, manager: "pwncat.manager.Manager", args):
        raise RawModeExit
