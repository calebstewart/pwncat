#!/usr/bin/env python3
from colorama import Fore, Style

import pwncat
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    parameter,
    StoreConstOnce,
    StoreForAction,
)


class Command(CommandDefinition):
    """
    Interface with the underlying enumeration module. This provides methods
    for enumerating, viewing and clearing cached facts about the victim.
    Types of enumeration data include the following options:

    * all - all known enumeration techniques
    * common - common useful information
    * suid - Set UID binaries on the remote host
    * passwords - Known passwords for remote users
    * keys - Known private keys found on the remote host
    
    Other enumeration data may be available which was dynamically registered by
    other ``pwncat`` modules.
    
    """

    PROG = "enum"
    ARGS = {
        "--show,-s": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="show",
            help="Find and display all facts of the given type",
        ),
        "--no-enumerate,-n": parameter(
            Complete.NONE,
            action="store_true",
            help="Do not perform actual enumeration; only print already enumerated values",
        ),
        "--type,-t": parameter(
            Complete.NONE, help="The type of enumeration data to query"
        ),
        "--flush,-f": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="flush",
            help="Flush the queried enumeration data from the database",
        ),
        "--provider,-p": parameter(
            Complete.NONE, help="The enumeration provider to filter by"
        ),
    }
    DEFAULTS = {"action": "help"}

    def run(self, args):

        # no arguments prints help
        if args.action == "help":
            self.parser.print_help()
            return

        if not args.type:
            args.type = "all"

        if args.action == "show":
            self.show_facts(args.type, args.provider)
        elif args.action == "flush":
            self.flush_facts(args.type, args.provider)

    def show_facts(self, typ: str, provider: str):
        """ Display known facts matching the criteria """

        if typ is not None:
            print(f"{Fore.YELLOW}{Style.BRIGHT}{typ.upper()} Facts{Style.RESET_ALL}")
            for fact in pwncat.victim.enumerate:
                if fact.type != typ:
                    continue
                if provider is not None and fact.source != provider:
                    continue
                print(f"  {fact.data} from {fact.source}")

    def flush_facts(self, typ: str, provider: str):
        """ Flush all facts that match criteria """

        pwncat.victim.enumerate.flush(typ, provider)
