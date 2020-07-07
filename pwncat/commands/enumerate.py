#!/usr/bin/env python3
import argparse
import textwrap
from typing import List, Dict

import pytablewriter
from colorama import Fore, Style
from pytablewriter import MarkdownTableWriter
from rich.progress import Progress, BarColumn

import pwncat
from pwncat import util
from pwncat.util import console
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreConstOnce,
    Group,
    StoreForAction,
    StoreConstForAction,
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
    There are various types of enumeration data which can be collected by
    pwncat. Some enumeration data is provided by "enumerator" modules which
    will be automatically run if you request a type which they provide. On
    the other hand, some enumeration is performed as a side-effect of other
    operations (normally a privilege escalation). This data is only stored
    when it is found organically. To find out what types are available, you
    should use the tab-completion at the local prompt. Some shortcuts are
    provided with the "enumeration groups" options below.
    
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
        ),
        "groups": Group(
            title="enumeration groups",
            description=(
                "common enumeration groups; these put together various "
                "groups of enumeration types which may be useful"
            ),
        ),
    }
    ARGS = {
        "--show,-s": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="show",
            group="action",
            help="Find and display all facts of the given type and provider",
        ),
        "--long,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="Show long description of enumeration results (only valid for --show)",
        ),
        "--no-enumerate,-n": Parameter(
            Complete.NONE,
            action="store_true",
            help="Do not perform actual enumeration; only print already enumerated values",
        ),
        "--type,-t": Parameter(
            Complete.CHOICES,
            action=StoreForAction(["show", "flush"]),
            nargs=1,
            choices=get_fact_types,
            metavar="TYPE",
            help="The type of enumeration data to query (only valid for --show/--flush)",
        ),
        "--flush,-f": Parameter(
            Complete.NONE,
            group="action",
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="flush",
            help=(
                "Flush the queried enumeration data from the database. "
                "This only flushed the data specified by the --type and "
                "--provider options. If no type or provider or specified, "
                "all data is flushed"
            ),
        ),
        "--provider,-p": Parameter(
            Complete.CHOICES,
            action=StoreForAction(["show", "flush"]),
            nargs=1,
            choices=get_provider_names,
            metavar="PROVIDER",
            help="The enumeration provider to filter by",
        ),
        "--report,-r": Parameter(
            Complete.LOCAL_FILE,
            group="action",
            action=ReportAction,
            nargs=1,
            help=(
                "Generate an enumeration report containing all enumeration "
                "data pwncat is capable of generating in a Markdown format."
            ),
        ),
        "--quick,-q": Parameter(
            Complete.NONE,
            action=StoreConstForAction(["show"]),
            dest="type",
            const=[
                "system.hostname",
                "system.arch",
                "system.distro",
                "system.kernel.version",
                "system.kernel.exploit",
                "system.network.hosts",
                "system.network",
                "writable_path",
            ],
            nargs=0,
            help="Activate the set of 'quick' enumeration types",
            group="groups",
        ),
        "--all,-a": Parameter(
            Complete.NONE,
            action=StoreConstForAction(["show"]),
            dest="type",
            const=None,
            nargs=0,
            help="Activate all enumeration types (this is the default)",
            group="groups",
        ),
    }
    DEFAULTS = {"action": "help"}

    def run(self, args):

        # no arguments prints help
        if args.action == "help":
            self.parser.print_help()
            return

        if args.action == "show":
            self.show_facts(args.type, args.provider, args.long)
        elif args.action == "flush":
            self.flush_facts(args.type, args.provider)
        elif args.action == "report":
            self.generate_report(args.report)

    def generate_report(self, report_path: str):
        """ Generate a markdown report of enumeration data for the remote host. This
        report is generated from all facts which pwncat is capable of enumerating.
        It does not need nor honor the type or provider options. """

        # Dictionary mapping type names to facts. Each type name is mapped
        # to a dictionary which maps sources to a list of facts. This makes
        # organizing the output report easier.
        report_data: Dict[str, Dict[str, List[pwncat.db.Fact]]] = {}
        system_details = []

        try:
            # Grab hostname
            hostname = pwncat.victim.enumerate.first("system.hostname").data
            system_details.append(["Hostname", util.escape_markdown(hostname)])
        except ValueError:
            hostname = "[unknown-hostname]"

        # Not provided by enumerate, but natively known due to our connection
        system_details.append(
            ["Primary Address", util.escape_markdown(pwncat.victim.host.ip)]
        )
        system_details.append(
            ["Derived Hash", util.escape_markdown(pwncat.victim.host.hash)]
        )

        try:
            # Grab distribution
            distro = pwncat.victim.enumerate.first("system.distro").data
            system_details.append(
                [
                    "Distribution",
                    util.escape_markdown(
                        f"{distro.name} ({distro.ident}) {distro.version}"
                    ),
                ]
            )
        except ValueError:
            pass

        try:
            # Grab the architecture
            arch = pwncat.victim.enumerate.first("system.arch").data
            system_details.append(["Architecture", util.escape_markdown(arch.arch)])
        except ValueError:
            pass

        try:
            # Grab kernel version
            kernel = pwncat.victim.enumerate.first("system.kernel.version").data
            system_details.append(
                [
                    "Kernel",
                    util.escape_markdown(
                        f"Linux Kernel {kernel.major}.{kernel.minor}.{kernel.patch}-{kernel.abi}"
                    ),
                ]
            )
        except ValueError:
            pass

        try:
            # Grab SELinux State
            selinux = pwncat.victim.enumerate.first("system.selinux").data
            system_details.append(["SELinux", util.escape_markdown(selinux.state)])
        except ValueError:
            pass

        try:
            # Grab ASLR State
            aslr = pwncat.victim.enumerate.first("system.aslr").data
            system_details.append(
                ["ASLR", "disabled" if aslr.state == 0 else "enabled"]
            )
        except ValueError:
            pass

        try:
            # Grab init system
            init = pwncat.victim.enumerate.first("system.init").data
            system_details.append(["Init", util.escape_markdown(str(init.init))])
        except ValueError:
            pass

        try:
            # Check if we are in a container
            container = pwncat.victim.enumerate.first("system.container").data
            system_details.append(["Container", util.escape_markdown(container.type)])
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

        # Note enumeration data we don't need anymore. These are handled above
        # in the system_details table which is output with the table_writer.
        ignore_types = [
            "system.hostname",
            "system.kernel.version",
            "system.distro",
            "system.init",
            "system.arch",
            "system.aslr",
            "system.container",
        ]

        # This is the list of known enumeration types that we want to
        # happen first in this order. Other types will still be output
        # but will be output in an arbitrary order following this list
        ordered_types = [
            # Sudo privileges
            "sudo",
            # Possible kernel exploits - very important
            "system.kernel.exploit",
            # Enumerated user passwords - very important
            "system.user.password",
            # Enumerated possible user private keys - very important
            "system.user.private_key",
            # Directories in our path that are writable
            "writable_path",
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

        with Progress(
            "enumerating report data",
            "•",
            "[cyan]{task.fields[status]}",
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("", status="initializing")
            for fact in pwncat.victim.enumerate():
                progress.update(task, status=str(fact.data))
                if fact.type in ignore_types:
                    continue
                if fact.type not in report_data:
                    report_data[fact.type] = {}
                if fact.source not in report_data[fact.type]:
                    report_data[fact.type][fact.source] = []
                report_data[fact.type][fact.source].append(fact)

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

            console.log(f"enumeration report written to [cyan]{report_path}[/cyan]")
        except OSError as exc:
            console.log(f"[red]error[/red]: [cyan]{report_path}[/cyan]: {exc}")

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
                filp.write(
                    f"- {util.escape_markdown(util.strip_ansi_escape(str(fact.data)))}\n"
                )

        filp.write("\n")

        for section in sections:
            filp.write(
                f"### {util.escape_markdown(util.strip_ansi_escape(str(section.data)))}\n\n"
            )
            filp.write(f"```\n{section.data.description}\n```\n\n")

    def show_facts(self, typ: str, provider: str, long: bool):
        """ Display known facts matching the criteria """

        data: Dict[str, Dict[str, List[pwncat.db.Fact]]] = {}

        types = typ if isinstance(typ, list) else [typ]

        with Progress(
            "enumerating facts",
            "•",
            "[cyan]{task.fields[status]}",
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("", status="initializing")
            for typ in types:
                for fact in pwncat.victim.enumerate.iter(
                    typ, filter=lambda f: provider is None or f.source == provider
                ):
                    progress.update(task, status=str(fact.data))
                    if fact.type not in data:
                        data[fact.type] = {}
                    if fact.source not in data[fact.type]:
                        data[fact.type][fact.source] = []
                    data[fact.type][fact.source].append(fact)

        for typ, sources in data.items():
            for source, facts in sources.items():
                console.print(
                    f"[bright_yellow]{typ.upper()}[/bright_yellow] Facts by [blue]{source}[/blue]"
                )
                for fact in facts:
                    console.print(f"  {fact.data}")
                    if long and getattr(fact.data, "description", None) is not None:
                        console.print(textwrap.indent(fact.data.description, "    "))

    def flush_facts(self, typ: str, provider: str):
        """ Flush all facts that match criteria """

        types = typ if isinstance(typ, list) else [typ]
        for typ in types:
            pwncat.victim.enumerate.flush(typ, provider)
