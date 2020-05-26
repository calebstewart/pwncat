#!/usr/bin/env python3
import argparse
import os
import textwrap
from typing import List, Dict

from colorama import Fore, Style

import pwncat
from pwncat import util
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreConstOnce,
    Group,
    StoreForAction,
)


class ReportAction(argparse.Action):
    """ Mirror the StoreConstOnce action, but also store the argument as the path
    to the local report. """

    def __call__(self, parser, namespace, values, option_string=None):
        if hasattr(self, "__action_seen"):
            raise argparse.ArgumentError(self, "only one action may be specified")
        setattr(namespace, "__action_seen", True)
        setattr(namespace, "action", "report")
        setattr(namespace, "report", values[0])


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

    def get_fact_types(self):
        if pwncat.victim is None or pwncat.victim.enumerate is None:
            return
        for typ, _ in pwncat.victim.enumerate.enumerators.items():
            yield typ

    def get_provider_names(self):
        if pwncat.victim is None or pwncat.victim.enumerate is None:
            return
        seen = []
        for fact in pwncat.victim.enumerate.iter(only_cached=True):
            if fact.source in seen:
                continue
            seen.append(fact.source)
            yield fact.source

    PROG = "enum"
    GROUPS = {
        "action": Group(
            title="enumeration actions",
            description="Exactly one action must be chosen from the below list.",
        )
    }
    ARGS = {
        "--show,-s": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="show",
            group="action",
            help="Find and display all facts of the given type",
        ),
        "--long,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="Show long description of enumeration results",
        ),
        "--no-enumerate,-n": Parameter(
            Complete.NONE,
            action="store_true",
            help="Do not perform actual enumeration; only print already enumerated values",
        ),
        "--type,-t": Parameter(
            Complete.CHOICES,
            choices=get_fact_types,
            metavar="TYPE",
            help="The type of enumeration data to query",
        ),
        "--flush,-f": Parameter(
            Complete.NONE,
            group="action",
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="flush",
            help="Flush the queried enumeration data from the database",
        ),
        "--provider,-p": Parameter(
            Complete.CHOICES,
            choices=get_provider_names,
            metavar="PROVIDER",
            help="The enumeration provider to filter by",
        ),
        "--report,-r": Parameter(
            Complete.LOCAL_FILE,
            group="action",
            action=ReportAction,
            nargs=1,
            help="Generate an enumeration report containing the specified enumeration data",
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
        elif args.action == "report":
            self.generate_report(args.report, args.type, args.provider)

    def generate_report(self, report_path: str, typ: str, provider: str):
        """ Generate a markdown report of enumeration data for the remote host """

        report_data: Dict[str, Dict[str, List[pwncat.db.Fact]]] = {}
        hostname = ""

        util.progress("enumerating report_data")
        for fact in pwncat.victim.enumerate.iter(
            typ, filter=lambda f: provider is None or f.source == provider
        ):
            util.progress(f"enumerating report_data: {fact.data}")
            if fact.type == "system.hostname":
                hostname = str(fact.data)
            if fact.type not in report_data:
                report_data[fact.type] = {}
            if fact.source not in report_data[fact.type]:
                report_data[fact.type][fact.source] = []
            report_data[fact.type][fact.source].append(fact)

        util.erase_progress()

        try:
            with open(report_path, "w") as filp:
                filp.write(f"# {hostname} - {pwncat.victim.host.ip}\n\n")
                for typ, sources in report_data.items():
                    filp.write(f"## {typ.upper()} Facts\n\n")
                    sections = []
                    for source, facts in sources.items():
                        for fact in facts:
                            if getattr(fact.data, "description", None) is not None:
                                sections.append(fact)
                                continue
                            filp.write(f"- {util.strip_ansi_escape(str(fact.data))}\n")

                    filp.write("\n")

                    for section in sections:
                        filp.write(
                            f"### {util.strip_ansi_escape(str(section.data))}\n\n"
                        )
                        filp.write(f"```\n{section.data.description}\n```\n\n")
            util.success(f"enumeration report written to {report_path}")
        except OSError:
            self.parser.error(f"{report_path}: failed to open output file")

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
