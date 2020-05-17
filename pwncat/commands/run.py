#!/usr/bin/env python3
import sys

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, parameter


class Command(CommandDefinition):

    PROG = "run"
    ARGS = {
        "argv": parameter(
            Complete.NONE, nargs="+", help="The command to run on the remote host"
        )
    }

    def run(self, args):
        sys.stdout.buffer.write(pwncat.victim.run(args.argv))
