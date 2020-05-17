#!/usr/bin/env python3
import subprocess

from pwncat.commands import CommandDefinition, Complete
from pwncat.commands.base import parameter


class Command(CommandDefinition):

    PROG = "local"
    ARGS = {
        "argv": parameter(
            Complete.NONE, nargs="+", help="the local shell command to run"
        )
    }
    LOCAL = True

    def run(self, args):
        subprocess.run(args.argv, shell=True)
