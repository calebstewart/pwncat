#!/usr/bin/env python3
from colorama import Fore

from pwncat import util
from pwncat.commands.base import CommandDefinition, Complete, parameter, StoreConstOnce
import pwncat


class Command(CommandDefinition):
    """
    Control the internal database cache of `pwncat`. This allows you to view
    and flush various caches which `pwncat` builds while running such as the
    SUID binary cache, the `which` cache and others.
    """

    PROG = "cache"
    ARGS = {
        "--flush,-f": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="flush",
            dest="action",
            help="Flush the contents of the specified cache",
        ),
        "--show,-s": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            const="show",
            dest="action",
            help="Show the contents of the specified cache",
        ),
        "cache": parameter(
            Complete.CHOICES,
            choices=["suid", "which", "users", "all"],
            help="A cache to operate on",
        ),
    }
    DEFAULTS = {"action": "show"}

    def run(self, args):

        if args.action == "show":
            if args.cache == "suid":
                self.show_suid_cache()
            elif args.cache == "which":
                self.show_which_cache()
            elif args.cache == "users":
                self.show_user_cache()
            elif args.cache == "all":
                util.error("all is only valid for the flush action")
        elif args.action == "flush":
            if args.cache == "suid" or args.cache == "all":
                self.flush_suid_cache()
            if args.cache == "which" or args.cache == "all":
                self.flush_which_cache()
            if args.cache == "users" or args.cache == "all":
                self.flush_user_cache()
            util.success(f"{args.cache} cache(s) flushed")

    def show_suid_cache(self):
        seen = []
        for binary in pwncat.victim.host.suid:
            if binary.path in seen:
                continue
            seen.append(binary.path)
            print(
                f" - {Fore.BLUE}{binary.path}{Fore.RESET} owned by "
                f"{Fore.GREEN}{pwncat.victim.find_user_by_id(binary.owner_id).name}{Fore.RESET}"
            )

    def show_which_cache(self):
        for binary in pwncat.victim.host.binaries:
            print(
                f" - {Fore.RED}{binary.name}{Fore.RESET}: {Fore.BLUE}{binary.path}{Fore.RESET}"
            )

    def show_user_cache(self):
        for user in pwncat.victim.host.users:
            print(
                f"name: {Fore.GREEN}{user.name}{Fore.RESET}, id: {Fore.YELLOW}{user.id}{Fore.RESET}, gid: {Fore.YELLOW}{user.gid}{Fore.RESET}"
            )
            print(f"  description: {user.fullname}")
            print(f"  home directory: {Fore.BLUE}{user.homedir}{Fore.RESET}")
            print(f"  shell: {Fore.BLUE}{user.shell}{Fore.RESET}")
            if user.hash:
                print(f"  hash: {Fore.RED}{user.hash}{Fore.RESET}")
            if user.password:
                print(f"  password: {Fore.RED}{user.password}{Fore.RESET}")

    def flush_suid_cache(self):
        while pwncat.victim.host.suid:
            pwncat.victim.session.delete(pwncat.victim.host.suid[0])
            del pwncat.victim.host.suid[0]

    def flush_which_cache(self):
        removed = []
        for binary in pwncat.victim.host.binaries:
            if (
                pwncat.victim.host.busybox is not None
                and pwncat.victim.host.busybox in binary.path
            ):
                continue
            removed.append(binary)
            pwncat.victim.session.delete(binary)

        pwncat.victim.session.commit()
        pwncat.victim.host = (
            pwncat.victim.session.query(pwncat.db.Host)
            .filter_by(id=pwncat.victim.host.id)
            .first()
        )

    def flush_user_cache(self):
        pwncat.victim.reload_users()
