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
            ["state"] + list(pwncat.victim.config.values) + list(pwncat.victim.users)
        )

        if pwncat.victim.config.module:
            options.extend(pwncat.victim.config.module.ARGUMENTS.keys())

        return options

    PROG = "set"
    ARGS = {
        "--password,-p": Parameter(
            Complete.NONE, action="store_true", help="set a user password",
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

    def run(self, args):
        if args.password:
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
            if (
                args.variable is not None
                and args.variable == "state"
                and args.value is not None
            ):
                try:
                    pwncat.victim.state = State._member_map_[args.value.upper()]
                except KeyError:
                    console.log(f"[red]error[/red]: {args.value}: invalid state")
            elif args.variable is not None and args.value is not None:
                try:
                    pwncat.victim.config.set(
                        args.variable, args.value, getattr(args, "global")
                    )
                    if args.variable == "db":
                        # We handle this specially to ensure the database is available
                        # as soon as this config is set
                        pwncat.victim.engine = create_engine(
                            pwncat.victim.config["db"], echo=False
                        )
                        pwncat.db.Base.metadata.create_all(pwncat.victim.engine)

                        # Create the session_maker and default session
                        pwncat.victim.session_maker = sessionmaker(
                            bind=pwncat.victim.engine
                        )
                        pwncat.victim.session = pwncat.victim.session_maker()
                except ValueError as exc:
                    console.log(f"[red]error[/red]: {exc}")
            elif args.variable is not None:
                value = pwncat.victim.config[args.variable]
                console.print(
                    f" [cyan]{args.variable}[/cyan] = [yellow]{repr(value)}[/yellow]"
                )
            else:
                for name in pwncat.victim.config:
                    value = pwncat.victim.config[name]
                    console.print(
                        f" [cyan]{name}[/cyan] = [yellow]{repr(value)}[/yellow]"
                    )
