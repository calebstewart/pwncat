#!/usr/bin/env python3
import textwrap
from typing import Dict, Type, Tuple, Iterator

from colorama import Fore, Style

import pwncat
from pwncat import util
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

    @property
    def installed_methods(self) -> Iterator[Tuple[str, str, PersistenceMethod]]:
        me = pwncat.victim.current_user
        for method in pwncat.victim.persist:
            if method.system and method.installed():
                yield (method.name, None, method)
            elif not method.system:
                if me.id == 0:
                    for user in pwncat.victim.users:
                        util.progress(f"checking {method.name} for: {user}")
                        if method.installed(user):
                            util.erase_progress()
                            yield (method.name, user, method)
                        util.erase_progress()
                else:
                    if method.installed(me.name):
                        yield (method.name, me.name, method)

    def run(self, args):

        if args.action == "status":
            ninstalled = 0
            for user, method in pwncat.victim.persist.installed:
                print(f" - {method.format(user)} installed")
                ninstalled += 1
            if not ninstalled:
                util.warn(
                    "no persistence methods observed as "
                    f"{Fore.GREEN}{pwncat.victim.whoami()}{Fore.RED}"
                )
            return
        elif args.action == "list":
            if args.method:
                try:
                    method = next(pwncat.victim.persist.find(args.method))
                    print(f"\033[4m{method.format()}{Style.RESET_ALL}")
                    print(textwrap.indent(textwrap.dedent(method.__doc__), "  "))
                except StopIteration:
                    util.error(f"{args.method}: no such persistence method")
            else:
                for method in pwncat.victim.persist:
                    print(f" - {method.format()}")
            return
        elif args.action == "clean":
            util.progress("cleaning persistence methods: ")
            for user, method in pwncat.victim.persist.installed:
                try:
                    util.progress(
                        f"cleaning persistance methods: {method.format(user)}"
                    )
                    pwncat.victim.persist.remove(method.name, user)
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

        # Grab the user we want to install the persistence as
        if args.user:
            user = args.user
        else:
            # Default is to install as current user
            user = pwncat.victim.whoami()

        try:
            if args.action == "install":
                pwncat.victim.persist.install(args.method, user)
            elif args.action == "remove":
                pwncat.victim.persist.remove(args.method, user)
        except PersistenceError as exc:
            util.error(f"{exc}")
