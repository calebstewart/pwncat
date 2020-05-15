#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition, Complete, parameter
from colorama import Fore


class Command(CommandDefinition):
    """ Alias an existing command with a new name. Specifying no alias or command
    will list all aliases. Specifying an alias with no command will remove the 
    alias if it exists. """

    def get_command_names(self):
        return [c.PROG for c in self.cmdparser.commands]

    PROG = "alias"
    ARGS = {
        "alias": parameter(Complete.NONE, help="name for the new alias", nargs="?"),
        "command": parameter(
            Complete.CHOICES,
            metavar="COMMAND",
            choices=get_command_names,
            help="the command the new alias will use",
            nargs="?",
        ),
    }
    LOCAL = True

    def run(self, args):
        if args.alias is None:
            for name, command in self.cmdparser.aliases.items():
                print(
                    f" {Fore.CYAN}{name}{Fore.RESET} \u2192 "
                    f"{Fore.YELLOW}{command.PROG}{Fore.RESET}"
                )
        elif args.command is not None:
            # This is safe because of "choices" in the argparser
            self.cmdparser.aliases[args.alias] = [
                c for c in self.cmdparser.commands if c.PROG == args.command
            ][0]
        else:
            del self.cmdparser.aliases[args.alias]
