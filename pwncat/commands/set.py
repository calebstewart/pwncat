#!/usr/bin/env python3
from colorama import Fore
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat import util


class Command(CommandDefinition):
    """ Set variable runtime variable parameters for pwncat """

    def get_config_variables(self):
        return ["state"] + list(self.pty.config.values)

    PROG = "set"
    ARGS = {
        "variable": parameter(
            Complete.CHOICES,
            nargs="?",
            choices=get_config_variables,
            metavar="VARIABLE",
            help="the variable name to modify",
        ),
        "value": parameter(
            Complete.LOCAL_FILE, nargs="?", help="the value for the given variable"
        ),
    }
    LOCAL = True

    def run(self, args):
        if (
            args.variable is not None
            and args.variable == "state"
            and args.value is not None
        ):
            try:
                self.pty.state = util.State._member_map_[args.value.upper()]
            except KeyError:
                util.error(f"{args.value}: invalid state")
        elif args.variable is not None and args.value is not None:
            try:
                self.pty.config[args.variable] = args.value
            except ValueError as exc:
                util.error(str(exc))
        elif args.variable is not None:
            value = self.pty.config[args.variable]
            print(
                f" {Fore.CYAN}{args.variable}{Fore.RESET} = "
                f"{Fore.YELLOW}{repr(value)}{Fore.RESET}"
            )
        else:
            for name in self.pty.config:
                value = self.pty.config[name]
                print(
                    f" {Fore.CYAN}{name}{Fore.RESET} = "
                    f"{Fore.YELLOW}{repr(value)}{Fore.RESET}"
                )
