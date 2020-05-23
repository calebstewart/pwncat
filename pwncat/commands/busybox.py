#!/usr/bin/env python3
from colorama import Fore
from sqlalchemy import func

import pwncat
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    parameter,
    StoreConstOnce,
    StoreForAction,
)
from pwncat import util


class Command(CommandDefinition):
    """ Manage installation of a known-good busybox binary on the remote system.
    After installing busybox, pwncat will be able to utilize it's functionality
    to augment or stabilize local binaries. This command can download a remote
    busybox binary appropriate for the remote architecture and then upload it
    to the remote system. """

    PROG = "busybox"
    ARGS = {
        "--list,-l": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="list",
            dest="action",
            help="List applets which the remote busybox provides",
        ),
        "--install,-i": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="install",
            dest="action",
            help="Install busybox on the remote host for use with pwncat",
        ),
        "--status,-s": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="status",
            dest="action",
            help="List the current busybox installation status",
        ),
        "--url,-u": parameter(
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

        if args.action == "list":
            if pwncat.victim.host.busybox is None:
                util.error(
                    "busybox hasn't been installed yet (hint: run 'busybox --install'"
                )
                return
            util.info("binaries which the remote busybox provides:")

            # Find all binaries which are provided by busybox
            provides = pwncat.victim.session.query(pwncat.db.Binary).filter(
                pwncat.db.Binary.path.contains(pwncat.victim.host.busybox),
                pwncat.db.Binary.host_id == pwncat.victim.host.id,
            )

            for binary in provides:
                print(f" * {binary.name}")
        elif args.action == "status":
            if pwncat.victim.host.busybox is None:
                util.error("busybox hasn't been installed yet")
                return
            util.info(
                f"busybox is installed to: {Fore.BLUE}{pwncat.victim.host.busybox}{Fore.RESET}"
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
            util.info(f"busybox provides {Fore.GREEN}{nprovides}{Fore.RESET} applets")
        elif args.action == "install":
            pwncat.victim.bootstrap_busybox(args.url)
