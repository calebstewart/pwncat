#!/usr/bin/env python3
import os
import pathlib

import pwncat
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """Change the local current working directory"""

    PROG = "lcd"
    ARGS = {
        "path": Parameter(Complete.LOCAL_FILE),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        # Expand `~`
        path = pathlib.Path(args.path).expanduser()

        # Ensure the directory exists
        if not path.is_dir():
            self.parser.error(f"{path}: not a directory")

        # Change to that directory
        os.chdir(str(path))
