#!/usr/bin/env python3
from prompt_toolkit.input.ansi_escape_sequences import REVERSE_ANSI_SEQUENCES
from prompt_toolkit.keys import ALL_KEYS, Keys

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, parameter
from pwncat.config import KeyType
from pwncat import util
from colorama import Fore
import string


class Command(CommandDefinition):

    PROG = "bind"
    ARGS = {
        "key": parameter(
            Complete.NONE,
            metavar="KEY",
            type=KeyType,
            help="The key to map after your prefix",
            nargs="?",
        ),
        "script": parameter(
            Complete.NONE, help="The script to run when the key is pressed", nargs="?",
        ),
    }
    LOCAL = True

    def run(self, args):
        if args.key is None:
            util.info("currently assigned key-bindings:")
            for key, binding in pwncat.victim.config.bindings.items():
                print(
                    f" {Fore.CYAN}{key}{Fore.RESET} = {Fore.YELLOW}{repr(binding)}{Fore.RESET}"
                )
        elif args.key is not None and args.script is None:
            if args.key in pwncat.victim.config.bindings:
                del pwncat.victim.config.bindings[args.key]
        else:
            pwncat.victim.config.bindings[args.key] = args.script
