#!/usr/bin/env python3
import textwrap
from typing import List, Dict

from colorama import Fore, Style

import pwncat
from pwncat import util
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
        "--long,-l": parameter(
            Complete.NONE,
            action="store_true",
            help="Show long description of enumeration results",
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

        # if not args.type:
        #     args.type = "all"

        if args.action == "show":
            self.show_facts(args.type, args.provider, args.long)
        elif args.action == "flush":
            self.flush_facts(args.type, args.provider)

    def show_facts(self, typ: str, provider: str, long: bool):
        """ Display known facts matching the criteria """

        facts: Dict[str, Dict[str, List[pwncat.db.Fact]]] = {}

        util.progress("enumerating facts")
        for fact in pwncat.victim.enumerate.iter(
            typ, filter=lambda f: provider is None or f.source == provider
        ):
            util.progress(f"enumerating facts: {fact.data}")
            if fact.type not in facts:
                facts[fact.type] = {}
            if fact.source not in facts[fact.type]:
                facts[fact.type][fact.source] = []
            facts[fact.type][fact.source].append(fact)

        util.erase_progress()

        for typ, sources in facts.items():
            for source, facts in sources.items():
                print(
                    f"{Style.BRIGHT}{Fore.YELLOW}{typ.upper()}{Fore.RESET} Facts by {Fore.BLUE}{source}{Style.RESET_ALL}"
                )
                for fact in facts:
                    print(f"  {fact.data}")
                    if long and getattr(fact.data, "description", None) is not None:
                        print(textwrap.indent(fact.data.description, "    "))

    def flush_facts(self, typ: str, provider: str):
        """ Flush all facts that match criteria """

        pwncat.victim.enumerate.flush(typ, provider)
