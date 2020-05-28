#!/usr/bin/env python3
import argparse
import textwrap
from typing import List, Dict

import pytablewriter
from colorama import Fore, Style
from pytablewriter import MarkdownTableWriter

import pwncat
from pwncat import util
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreConstOnce,
    Group,
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

        system_details = []

        try:
            # Grab hostname
            hostname = pwncat.victim.enumerate.first("system.hostname").data
            system_details.append(["Hostname", hostname])
        except ValueError:
            hostname = "[unknown-hostname]"

        # Not provided by enumerate, but natively known due to our connection
        system_details.append(["Primary Address", pwncat.victim.host.ip])
        system_details.append(["Derived Hash", pwncat.victim.host.hash])

        try:
            # Grab distribution
            distro = pwncat.victim.enumerate.first("system.distro").data
            system_details.append(
                ["Distribution", f"{distro.name} ({distro.ident}) {distro.version}"]
            )
        except ValueError:
            pass

        try:
            # Grab the architecture
            arch = pwncat.victim.enumerate.first("system.arch").data
            system_details.append(["Architecture", arch.arch])
        except ValueError:
            pass

        try:
            # Grab kernel version
            kernel = pwncat.victim.enumerate.first("system.kernel.version").data
            system_details.append(
                [
                    "Kernel",
                    f"Linux Kernel {kernel.major}.{kernel.minor}.{kernel.patch}-{kernel.abi}",
                ]
            )
        except ValueError:
            pass

        try:
            # Grab init system
            init = pwncat.victim.enumerate.first("system.init").data
            system_details.append(["Init", init.init])
        except ValueError:
            pass

        # Build the table writer for the main section
        table_writer = MarkdownTableWriter()
        table_writer.headers = ["Property", "Value"]
        table_writer.column_styles = [
            pytablewriter.style.Style(align="right"),
            pytablewriter.style.Style(align="center"),
        ]
        table_writer.value_matrix = system_details
        table_writer.margin = 1

        # Note enumeration data we don't need anymore
        ignore_types = [
            "system.hostname",
            "system.kernel.version",
            "system.distro",
            "system.init",
            "system.arch",
        ]

        # This is the list of known enumeration types that we want to
        # happen first in this order. Other types will still be output
        # but will be output in an arbitrary order following this list
        ordered_types = [
            # Possible kernel exploits - very important
            "system.kernel.exploit",
            # Enumerated user passwords - very important
            "system.user.password",
            # Enumerated possible user private keys - very important
            "system.user.private_key",
        ]

        # These types are very noisy. They are important for full enumeration,
        # but are better suited for the end of the list. These are output last
        # no matter what in this order.
        noisy_types = [
            # System services. There's normally a lot of these
            "system.service",
            # Installed packages. There's *always* a lot of these
            "system.package",
        ]

        util.progress("enumerating report_data")
        for fact in pwncat.victim.enumerate.iter(
            typ, filter=lambda f: provider is None or f.source == provider
        ):
            util.progress(f"enumerating report_data: {fact.data}")
            if fact.type in ignore_types:
                continue
            if fact.type not in report_data:
                report_data[fact.type] = {}
            if fact.source not in report_data[fact.type]:
                report_data[fact.type][fact.source] = []
            report_data[fact.type][fact.source].append(fact)

        util.erase_progress()

        try:
            with open(report_path, "w") as filp:
                filp.write(f"# {hostname} - {pwncat.victim.host.ip}\n\n")

                # Write the system info table
                table_writer.dump(filp, close_after_write=False)
                filp.write("\n")

                # output ordered types first
                for typ in ordered_types:
                    if typ not in report_data:
                        continue
                    self.render_section(filp, typ, report_data[typ])

                # output everything that's not a ordered or noisy type
                for typ, sources in report_data.items():
                    if typ in ordered_types or typ in noisy_types:
                        continue
                    self.render_section(filp, typ, sources)

                # Output the noisy types
                for typ in noisy_types:
                    if typ not in report_data:
                        continue
                    self.render_section(filp, typ, report_data[typ])

            util.success(f"enumeration report written to {report_path}")
        except OSError:
            self.parser.error(f"{report_path}: failed to open output file")

    def render_section(self, filp, typ: str, sources: Dict[str, List[pwncat.db.Fact]]):
        """
        Render the given facts all of the given type to the report pointed to by the open file
        filp.

        :param filp: the open file containing the report
        :param typ: the type all of these facts provide
        :param sources: a dictionary of sources->fact list
        """

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
            filp.write(f"### {util.strip_ansi_escape(str(section.data))}\n\n")
            filp.write(f"```\n{section.data.description}\n```\n\n")

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
