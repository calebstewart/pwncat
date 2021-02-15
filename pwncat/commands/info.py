#!/usr/bin/env python3
import textwrap

from rich.table import Table
from rich import box

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console


class Command(CommandDefinition):
    """ View info about a module """

    def get_module_choices(self):
        if self.manager.target is None:
            return

        yield from [module.name for module in self.manager.target.find_module("*")]

    PROG = "info"
    ARGS = {
        "module": Parameter(
            Complete.CHOICES,
            choices=get_module_choices,
            metavar="MODULE",
            help="The module to view information on",
            nargs="?",
        )
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        if not args.module and manager.config.module is None:
            console.log("[red]error[/red]: no module specified")
            return

        if args.module:
            try:
                module = list(manager.target.find_module(args.module, exact=True))[0]
            except IndexError:
                console.log(f"[red]error[/red]: {args.module}: no such module")
                return
        else:
            module = manager.config.module

        console.print(
            f"[bold underline]Module [cyan]{module.name}[/cyan][/bold underline]"
        )
        console.print(
            textwrap.indent(textwrap.dedent(module.__doc__.strip("\n")), " ") + "\n"
        )

        table = Table("Argument", "Default", "Help", box=box.MINIMAL_DOUBLE_HEAD)
        for arg, info in module.ARGUMENTS.items():
            if info.default is pwncat.modules.NoValue:
                default = ""
            else:
                default = info.default
            table.add_row(arg, str(default), info.help)

        console.print(table)
