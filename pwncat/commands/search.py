#!/usr/bin/env python3
import textwrap

from rich import box
from rich.table import Table, Column

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """View info about a module"""

    PROG = "search"
    ARGS = {
        "module": Parameter(
            Complete.NONE,
            help="glob pattern",
        )
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        modules = list(manager.target.find_module(f"*{args.module}*"))
        min_width = max(
            len(module.name.removeprefix("agnostic.")) for module in modules
        )

        table = Table(
            Column(header="Name", style="cyan", min_width=min_width),
            Column(header="Description"),
            title="Results",
            box=box.MINIMAL_DOUBLE_HEAD,
            expand=True,
        )

        for module in modules:
            # Rich will ellipsize the column, but we need to squeeze
            # white space and remove newlines. `textwrap.shorten` is
            # the easiest way to do that, so we use a large size for
            # width.
            description = module.__doc__ if module.__doc__ is not None else ""
            module_name = module.name.removeprefix("agnostic.")

            if self.manager.target is not None:
                module_name = module_name.removeprefix(
                    self.manager.target.platform.name + "."
                )

            table.add_row(
                f"[cyan]{module_name}[/cyan]",
                textwrap.shorten(
                    description.replace("\n", " "), width=80, placeholder="..."
                ),
            )

        console.print(table)
