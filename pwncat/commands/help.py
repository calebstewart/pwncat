#!/usr/bin/env python3
import textwrap

import pwncat
from pwncat.commands import CommandParser
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat import util


class Command(CommandDefinition):
    """ List known commands and print their associated help documentation. """

    PROG = "help"
    ARGS = {"topic": parameter(Complete.NONE, nargs="?")}
    LOCAL = True

    def run(self, args):
        if args.topic:
            for command in pwncat.victim.command_parser.commands:
                if command.PROG == args.topic:
                    if command.parser is not None:
                        command.parser.print_help()
                    else:
                        print(textwrap.dedent(command.__doc__).strip())
                    break
        else:
            util.info("the following commands are available:")
            for command in pwncat.victim.command_parser.commands:
                print(f" * {command.PROG}")
