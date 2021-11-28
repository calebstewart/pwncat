#!/usr/bin/env python3
from pathlib import Path

import pwncat
from pwncat.util import console
from pwncat.commands import CommandDefinition


class Command(CommandDefinition):
    """Print the local current working directory"""

    PROG = "lpwd"
    ARGS = {}

    def run(self, manager: "pwncat.manager.Manager", args):

        console.print(Path.cwd())
