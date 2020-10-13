#!/usr/bin/env python3
import textwrap

import pwncat
from pwncat.commands import CommandParser
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console


class Command(CommandDefinition):
    """ List known commands and print their associated help documentation. """

    def get_command_names(self):
        if pwncat.victim and pwncat.parser:
            return [c.PROG for c in pwncat.parser.commands]
        return []

    PROG = "help"
    ARGS = {"topic": Parameter(Complete.CHOICES, choices=get_command_names, nargs="?")}
    LOCAL = True

    def run(self, args):
        if args.topic:
            for command in pwncat.parser.commands:
                if command.PROG == args.topic:
                    if command.parser is not None:
                        command.parser.print_help()
                    else:
                        console.print(textwrap.dedent(command.__doc__).strip())
                    break
        else:
            for command in pwncat.parser.commands:
                console.print(f" - {command.PROG}")
