import pwncat
from pwncat.commands import CommandDefinition
from pwncat.commands.base import Parameter, Complete


class Command(CommandDefinition):

    PROG = "shortcut"
    ARGS = {
        "prefix": Parameter(
            Complete.NONE, help="the prefix character used for the shortcut"
        ),
        "command": Parameter(Complete.NONE, help="the command to execute"),
    }
    LOCAL = True

    def run(self, args):

        for command in pwncat.parser.commands:
            if command.PROG == args.command:
                pwncat.parser.shortcuts[args.prefix] = command
                return

        self.parser.error(f"{args.command}: no such command")
