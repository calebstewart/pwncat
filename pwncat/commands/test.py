#!/usr/bin/env python3
from pygments.token import *

from pwncat.commands.base import CommandDefinition, Complete, parameter


class Command(CommandDefinition):
    """ Command Description """

    PROG = "test"
    ARGS = {
        "--remote,-r": parameter(
            Complete.REMOTE_FILE, Name.LABEL, help="Argument Help"
        ),
        "--local,-l": parameter(Complete.LOCAL_FILE, Name.LABEL, help="Argument Help"),
        "--choice,-c": parameter(
            Complete.CHOICES,
            Name.LABEL,
            choices=["one", "two", "three"],
            help="Select one!",
        ),
    }

    def run(self, args):

        print(args.arg)
