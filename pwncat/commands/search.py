#!/usr/bin/env python3
import textwrap

from rich.table import Table, Column
from rich import box

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console


class Command(CommandDefinition):
    """ View info about a module """

    def get_module_choices(self):
        yield from [module.name for module in pwncat.modules.match("*")]

    PROG = "search"
    ARGS = {"module": Parameter(Complete.NONE, help="glob pattern",)}

    def run(self, args):

        table = Table(
            Column(header="Name", ratio=0.2),
            Column(header="Description", no_wrap=True, ratio=0.8),
            title="Results",
            box=box.MINIMAL_DOUBLE_HEAD,
            expand=True,
        )

        for module in pwncat.modules.match(f"*{args.module}*"):
            # Rich will ellipsize the column, but we need to squeze
            # white space and remove newlines. `textwrap.shorten` is
            # the easiest way to do that, so we use a large size for
            # width.
            description = module.__doc__ if module.__doc__ is not None else ""
            table.add_row(
                f"[cyan]{module.name}[/cyan]",
                textwrap.shorten(
                    description.replace("\n", " "), width=200, placeholder="..."
                ),
            )

        console.print(table)
