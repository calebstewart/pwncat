#!/usr/bin/env python3
from colorama import Fore
from sqlalchemy import func

import pwncat
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreConstOnce,
    StoreForAction,
)
from pwncat.util import console


class Command(CommandDefinition):
    """ Manage installation of a known-good busybox binary on the remote system.
    After installing busybox, pwncat will be able to utilize it's functionality
    to augment or stabilize local binaries. This command can download a remote
    busybox binary appropriate for the remote architecture and then upload it
    to the remote system. """

    PROG = "busybox"
    ARGS = {
        "--list,-l": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="list",
            dest="action",
            help="List applets which the remote busybox provides",
        ),
        "--install,-i": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="install",
            dest="action",
            help="Install busybox on the remote host for use with pwncat",
        ),
        "--status,-s": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="status",
            dest="action",
            help="List the current busybox installation status",
        ),
        "--url,-u": Parameter(
            Complete.NONE,
            action=StoreForAction(["install"]),
            nargs=1,
            help="The base URL to download busybox binaries from (default: 1.31.0-defconfig-multiarch-musl)",
            default=(
                "https://busybox.net/downloads/binaries/1.31.0-defconfig-multiarch-musl/"
            ),
        ),
    }
    DEFAULTS = {"action": "status"}

    def run(self, args):

        if args.action == "install":
            pwncat.victim.bootstrap_busybox(args.url)
        elif args.action == "list":
            if pwncat.victim.host.busybox is None:
                console.log(
                    "[red]error[/red]: "
                    "busybox is not installed (hint: run 'busybox --install')"
                )
                return

            # Find all binaries which are provided by busybox
            provides = pwncat.victim.session.query(pwncat.db.Binary).filter(
                pwncat.db.Binary.path.contains(pwncat.victim.host.busybox),
                pwncat.db.Binary.host_id == pwncat.victim.host.id,
            )

            for binary in provides:
                console.print(f" - {binary.name}")
        elif args.action == "status":
            if pwncat.victim.host.busybox is None:
                console.log("[red]error[/red]: busybox hasn't been installed yet")
                return
            console.log(
                f"busybox is installed to: [blue]{pwncat.victim.host.busybox}[/blue]"
            )

            # Find all binaries which are provided from busybox
            nprovides = (
                pwncat.victim.session.query(pwncat.db.Binary)
                .filter(
                    pwncat.db.Binary.path.contains(pwncat.victim.host.busybox),
                    pwncat.db.Binary.host_id == pwncat.victim.host.id,
                )
                .with_entities(func.count())
                .scalar()
            )
            console.log(f"busybox provides [green]{nprovides}[/green] applets")
