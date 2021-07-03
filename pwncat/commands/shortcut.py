from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):

    PROG = "shortcut"
    ARGS = {
        "prefix": Parameter(
            Complete.NONE, help="the prefix character used for the shortcut"
        ),
        "command": Parameter(Complete.NONE, help="the command to execute"),
    }
    LOCAL = True

    def run(self, manager, args):

        for command in manager.parser.commands:
            if command.PROG == args.command:
                manager.parser.shortcuts[args.prefix] = command
                return

        self.parser.error(f"{args.command}: no such command")
