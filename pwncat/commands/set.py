#!/usr/bin/env python3
from colorama import Fore
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat import util


class Command(CommandDefinition):
    """ Set variable runtime variable parameters for pwncat """

    def get_config_variables(self):
        return ["state"] + list(pwncat.victim.config.values) + list(pwncat.victim.users)

    PROG = "set"
    ARGS = {
        "--password,-p": parameter(
            Complete.NONE, action="store_true", help="set a user password",
        ),
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
        if args.password:
            if args.variable is None:
                found = False
                for user, props in pwncat.victim.users.items():
                    if "password" in props and props["password"] is not None:
                        print(
                            f" - {Fore.GREEN}{user}{Fore.RESET} -> {Fore.RED}{repr(props['password'])}{Fore.RESET}"
                        )
                        found = True
                if not found:
                    util.warn("no known user passwords")
            else:
                if args.variable not in pwncat.victim.users:
                    self.parser.error(f"{args.variable}: no such user")
                print(
                    f" - {Fore.GREEN}{args.variable}{Fore.RESET} -> {Fore.RED}{repr(args.value)}{Fore.RESET}"
                )
                pwncat.victim.users[args.variable]["password"] = args.value
        else:
            if (
                args.variable is not None
                and args.variable == "state"
                and args.value is not None
            ):
                try:
                    pwncat.victim.state = util.State._member_map_[args.value.upper()]
                except KeyError:
                    util.error(f"{args.value}: invalid state")
            elif args.variable is not None and args.value is not None:
                try:
                    pwncat.victim.config[args.variable] = args.value
                    if args.variable == "db":
                        # We handle this specially to ensure the database is available
                        # as soon as this config is set
                        pwncat.victim.engine = create_engine(
                            pwncat.victim.config["db"], echo=False
                        )
                        pwncat.db.Base.metadata.create_all(pwncat.victim.engine)

                        # Create the session_maker and default session
                        if pwncat.victim.session is None:
                            pwncat.victim.session_maker = sessionmaker(
                                bind=pwncat.victim.engine
                            )
                            pwncat.victim.session = pwncat.victim.session_maker()
                except ValueError as exc:
                    util.error(str(exc))
            elif args.variable is not None:
                value = pwncat.victim.config[args.variable]
                print(
                    f" {Fore.CYAN}{args.variable}{Fore.RESET} = "
                    f"{Fore.YELLOW}{repr(value)}{Fore.RESET}"
                )
            else:
                for name in pwncat.victim.config:
                    value = pwncat.victim.config[name]
                    print(
                        f" {Fore.CYAN}{name}{Fore.RESET} = "
                        f"{Fore.YELLOW}{repr(value)}{Fore.RESET}"
                    )
