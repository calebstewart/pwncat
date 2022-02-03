#!/usr/bin/env python3

from pathlib import Path

import pwncat
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Load modules from the specified directory. This does not remove
    currently loaded modules, but may replace modules which were already
    loaded. Also, prior to loading any specified modules, the standard
    modules are loaded. This normally happens only when modules are first
    utilized. This ensures that a standard module does not shadow a custom
    module. In fact, the opposite may happen in a custom module is defined
    with the same name as a standard module.
    """

    PROG = "load"
    ARGS = {
        "path": Parameter(
            Complete.LOCAL_FILE,
            help="Path to a python package directory to load modules from",
            nargs="+",
        ),
        "--force,-f": Parameter(
            Complete.NONE,
            help="Force loading the given module(s) even if they were already loaded.",
            action="store_true",
            default=False,
        ),
        "--reload,-r": Parameter(
            Complete.NONE,
            help="Synonym for --force",
            action="store_true",
            dest="force",
        ),
    }
    DEFAULTS = {}
    LOCAL = True

    def run(self, manager: "pwncat.manager.Manager", args):

        # Python's pkgutil.walk_packages doesn't produce an error
        # if the path doesn't exist, so we double check that each
        # provided path exists prior to calling it.
        for path in args.path:
            if not Path(path).expanduser().exists():
                self.parser.error(f"{path}: no such file or directory")

        manager.load_modules(*args.path, force=args.force)
