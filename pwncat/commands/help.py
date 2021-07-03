#!/usr/bin/env python3
import textwrap

import rich.box
from rich.table import Table, Column

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """List known commands and print their associated help documentation."""

    def get_command_names(self):
        try:
            # Because we are initialized prior to `manager.parser`,
            # we have to wrap this in a try-except block.
            yield from [cmd.PROG for cmd in self.manager.parser.commands]
        except AttributeError:
            return

    PROG = "help"
    ARGS = {"topic": Parameter(Complete.CHOICES, choices=get_command_names, nargs="?")}
    LOCAL = True

    def run(self, manager: "pwncat.manager.Manager", args):
        if args.topic:
            for command in manager.parser.commands:
                if command.PROG == args.topic:
                    if command.parser is not None:
                        command.parser.print_help()
                    else:
                        console.print(textwrap.dedent(command.__doc__).strip())
                    break
        else:
            table = Table(
                Column("Command", style="green"),
                Column("Description", no_wrap=True),
                box=rich.box.SIMPLE,
            )

            for command in manager.parser.commands:
                doc = command.__doc__
                if doc is None:
                    doc = ""
                else:
                    doc = textwrap.shorten(
                        textwrap.dedent(doc).strip().replace("\n", ""), 60
                    )

                table.add_row(command.PROG, doc)

            console.print(table)
