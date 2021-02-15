#!/usr/bin/env python3
import textwrap

import pwncat
from pwncat.commands import CommandParser
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console


class Command(CommandDefinition):
    """ List known commands and print their associated help documentation. """

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
            for command in manager.parser.commands:
                console.print(f" - {command.PROG}")
