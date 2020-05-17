import pwncat
from pwncat.commands import CommandDefinition
from pwncat.commands.base import parameter, Complete


class Command(CommandDefinition):

    PROG = "shortcut"
    ARGS = {
        "prefix": parameter(
            Complete.NONE, help="the prefix character used for the shortcut"
        ),
        "command": parameter(Complete.NONE, help="the command to execute"),
    }
    LOCAL = True

    def run(self, args):

        for command in pwncat.victim.command_parser.commands:
            if command.PROG == args.command:
                pwncat.victim.command_parser.shortcuts[args.prefix] = command
                return

        self.parser.error(f"{args.command}: no such command")
