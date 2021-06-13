#!/usr/bin/env python3

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition, get_module_choices


class Command(CommandDefinition):
    """ Set the currently used module in the config handler """

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

    def run(self, manager: "pwncat.manager.Manager", args):

        try:
            module = list(manager.target.find_module(args.module, exact=True))[0]
        except IndexError:
            console.log(f"[red]error[/red]: {args.module}: no such module")
            return

        manager.target.config.use(module)
