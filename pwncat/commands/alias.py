#!/usr/bin/env python3
from colorama import Fore

import pwncat
from pwncat.util import console
from pwncat.commands.base import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """Alias an existing command with a new name. Specifying no alias or command
    will list all aliases. Specifying an alias with no command will remove the
    alias if it exists."""

    def get_command_names(self):
        return [c.PROG for c in self.manager.parser.commands]

    PROG = "alias"
    ARGS = {
        "alias": Parameter(Complete.NONE, help="name for the new alias", nargs="?"),
        "command": Parameter(
            Complete.CHOICES,
            metavar="COMMAND",
            choices=get_command_names,
            help="the command the new alias will use",
            nargs="?",
        ),
    }
    LOCAL = True

    def run(self, manager, args):
        if args.alias is None:
            for name, command in manager.parser.aliases.items():
                console.print(
                    f" [cyan]{name}[/cyan] \u2192 [yellow]{command.PROG}[/yellow]"
                )
        elif args.command is not None:
            # This is safe because of "choices" in the argparser
            manager.parser.aliases[args.alias] = [
                c for c in manager.parser.commands if c.PROG == args.command
            ][0]
        else:
            del manager.parser.aliases[args.alias]
