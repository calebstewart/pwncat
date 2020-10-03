#!/usr/bin/env python3

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console


class Command(CommandDefinition):
    """ Set the currently used module in the config handler """

    def get_module_choices(self):
        yield from [module.name for module in pwncat.modules.match(".*")]

    PROG = "use"
    ARGS = {
        "module": Parameter(
            Complete.CHOICES,
            choices=get_module_choices,
            metavar="MODULE",
            help="the module to use",
        )
    }
    LOCAL = False

    def run(self, args):

        try:
            module = pwncat.modules.find(args.module)
        except KeyError:
            console.log(f"[red]error[/red]: {args.module}: invalid module name")
            return

        pwncat.victim.config.use(module)
