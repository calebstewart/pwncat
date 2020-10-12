#!/usr/bin/env python3
from prompt_toolkit.input.ansi_escape_sequences import REVERSE_ANSI_SEQUENCES
from prompt_toolkit.keys import ALL_KEYS, Keys

import pwncat
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.config import KeyType
from pwncat.util import console
from colorama import Fore
import string


class Command(CommandDefinition):

    PROG = "bind"
    ARGS = {
        "key": Parameter(
            Complete.NONE,
            metavar="KEY",
            type=KeyType,
            help="The key to map after your prefix",
            nargs="?",
        ),
        "script": Parameter(
            Complete.NONE, help="The script to run when the key is pressed", nargs="?",
        ),
    }
    LOCAL = True

    def run(self, args):
        if args.key is None:
            for key, binding in pwncat.config.bindings.items():
                console.print(f" [cyan]{key}[/cyan] = [yellow]{repr(binding)}[/yellow]")
        elif args.key is not None and args.script is None:
            if args.key in pwncat.config.bindings:
                del pwncat.config.bindings[args.key]
        else:
            pwncat.config.bindings[args.key] = args.script
