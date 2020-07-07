#!/usr/bin/env python3
import textwrap
from typing import Dict, Type, Tuple, Iterator

from colorama import Fore, Style
from rich.progress import (
    BarColumn,
    DownloadColumn,
    TextColumn,
    TransferSpeedColumn,
    TimeRemainingColumn,
    Progress,
    TaskID,
)

import pwncat
from pwncat.util import console
from pwncat.commands.base import CommandDefinition, Complete, Parameter, StoreConstOnce
from pwncat.persist import PersistenceMethod, PersistenceError


class Command(CommandDefinition):
    """ Manage various persistence methods on the remote host """

    def get_method_choices(self):
        return [method.name for method in pwncat.victim.persist]

    def get_user_choices(self):
        """ Get the user options """
        current = pwncat.victim.current_user
        if current.id == 0:
            return [name for name in pwncat.victim.users]
        else:
            return [current.name]

    PROG = "persist"
    ARGS = {
        "--method,-m": Parameter(
            Complete.CHOICES,
            metavar="METHOD",
            help="Select a persistence method to deploy",
            choices=get_method_choices,
        ),
        "--user,-u": Parameter(
            Complete.CHOICES,
            metavar="USER",
            help="For non-system persistence modules, the user to install as (only valid if currently UID 0)",
            choices=get_user_choices,
        ),
        "--status,-s": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="status",
            help="Check the status of the given persistence method",
        ),
        "--install,-i": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="install",
            help="Install the selected persistence method",
        ),
        "--list,-l": Parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="list",
            help="List all available persistence methods",
        ),
        "--remove,-r": Parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="remove",
            help="Remove the selected persistence method",
        ),
        "--clean,-c": Parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="clean",
            help="Remove all installed persistence methods",
        ),
    }
    DEFAULTS = {"action": "status"}

    # List of available persistence methods
    METHODS: Dict[str, Type["PersistenceMethod"]] = {}

    def show_status(self):
        """ Show the list of installed methods """

        ninstalled = 0
        for user, method in pwncat.victim.persist.installed:
            console.print(f" - {method.format(user)} installed")
            ninstalled += 1
        if not ninstalled:
            console.log("[yellow]warning[/yellow]: no persistence methods installed")

    def list_methods(self, method):
        """ List available methods or help for a specific method """

        if method:
            try:
                method = next(pwncat.victim.persist.find(method))
                console.print(f"[underline bold]{method.format()}")
                console.print(textwrap.indent(textwrap.dedent(method.__doc__), "  "))
            except StopIteration:
                console.log(f"[red]error[/red]: {method}: no such persistence method")
        else:
            for method in pwncat.victim.persist:
                console.print(f" - {method.format()}")

    def clean_methods(self):
        """ Remove all persistence methods from the victim """

        with Progress(
            "cleaning",
            "{task.fields[method]}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=console,
        ) as progress:
            installed = list(pwncat.victim.persist.installed)

            task = progress.add_task("", method="initializing", total=len(installed))

            for user, method in installed:
                try:
                    progress.update(task, method=method.format(user))
                    pwncat.victim.persist.remove(method.name, user)
                except PersistenceError as exc:
                    progress.log(
                        f"[yellow]warning[/yellow]: {method.format(user)}: "
                        f"removal failed: {exc}"
                    )
                progress.update(task, advance=1)

            progress.update(task, method="[bold green]complete")

    def run(self, args):

        try:
            if args.action == "status":
                self.show_status()
            elif args.action == "list":
                self.list_methods(args.method)
            elif args.action == "clean":
                self.clean_methods()
            elif args.action == "install":
                pwncat.victim.persist.install(
                    args.method, args.user if args.user else pwncat.victim.whoami()
                )
            elif args.action == "remove":
                pwncat.victim.persist.remove(
                    args.method, args.user if args.user else pwncat.victim.whoami()
                )
            elif args.method is None:
                self.parser.error("no method specified")
                return
        except PersistenceError as exc:
            console.log(f"[red]error[/red]: {exc}")
