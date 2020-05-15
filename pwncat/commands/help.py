#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat import util


class Command(CommandDefinition):
    """ List known commands and print their associated help documentation. """

    def get_command_names(self):
        """ Get the list of known commands """
        return [c.PROG for c in self.cmdparser.commands]

    PROG = "help"
    ARGS = {"topic": parameter(Complete.CHOICES, choices=get_command_names, nargs="?")}

    def run(self, args):
        if args.topic:
            for command in self.cmdparser.commands:
                if command.PROG == args.topic:
                    command.parser.print_help()
                    break
        else:
            util.info("the following commands are available:")
            for command in self.cmdparser.commands:
                print(f" * {command.PROG}")
