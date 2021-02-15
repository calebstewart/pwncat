#!/usr/bin/env python3

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter


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
        )
    }
    DEFAULTS = {}
    LOCAL = True

    def run(self, manager: "pwncat.manager.Manager", args):

        manager.load_modules(args.path)
