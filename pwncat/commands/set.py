#!/usr/bin/env python3
from colorama import Fore
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console, State


class Command(CommandDefinition):
    """ Set variable runtime variable parameters for pwncat """

    def get_config_variables(self):
        options = (
            ["state"]
            + list(self.manager.config.values)
            # + list(self.manager.victim.users)
        )

        if self.manager.config.module:
            options.extend(self.manager.config.module.ARGUMENTS.keys())

        return options

    PROG = "set"
    ARGS = {
        "--password,-p": Parameter(
            Complete.NONE,
            action="store_true",
            help="set a user password",
        ),
        "--global,-g": Parameter(
            Complete.NONE,
            action="store_true",
            help="Set a global configuration",
            default=False,
        ),
        "variable": Parameter(
            Complete.CHOICES,
            nargs="?",
            choices=get_config_variables,
            metavar="VARIABLE",
            help="the variable name to modify",
        ),
        "value": Parameter(
            Complete.LOCAL_FILE, nargs="?", help="the value for the given variable"
        ),
    }
    LOCAL = True

    def run(self, manager, args):
        if args.password:
            manager.log(
                "[red]error[/red]: user interaction not supported in new framework (yet)"
            )
            return
            if args.variable is None:
                found = False
                for name, user in pwncat.victim.users.items():
                    if user.password is not None:
                        console.print(
                            f" - [green]{user}[/green] -> [red]{repr(user.password)}[/red]"
                        )
                        found = True
                if not found:
                    console.log("[yellow]warning[/yellow]: no known user passwords")
            else:
                if args.variable not in pwncat.victim.users:
                    self.parser.error(f"{args.variable}: no such user")
                console.print(
                    f" - [green]{args.variable}[/green] -> [red]{repr(args.value)}[/red]"
                )
                pwncat.victim.users[args.variable].password = args.value
        else:
            if args.variable is not None and args.value is not None:
                try:
                    if manager.sessions and args.variable == "db":
                        raise ValueError("cannot change database with running session")
                    manager.config.set(
                        args.variable, args.value, getattr(args, "global")
                    )
                    if args.variable == "db":
                        # Ensure the database is re-opened, if it was already
                        manager.open_database()
                except ValueError as exc:
                    console.log(f"[red]error[/red]: {exc}")
            elif args.variable is not None:
                value = manager.config[args.variable]
                console.print(
                    f" [cyan]{args.variable}[/cyan] = [yellow]{repr(value)}[/yellow]"
                )
            else:
                for name in manager.config:
                    value = manager.config[name]
                    console.print(
                        f" [cyan]{name}[/cyan] = [yellow]{repr(value)}[/yellow]"
                    )
