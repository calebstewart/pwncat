#!/usr/bin/env python3
import string

from colorama import Fore
from prompt_toolkit.keys import ALL_KEYS, Keys
from prompt_toolkit.input.ansi_escape_sequences import REVERSE_ANSI_SEQUENCES

import pwncat
from pwncat.util import console
from pwncat.config import KeyType
from pwncat.commands.base import Complete, Parameter, CommandDefinition


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
            Complete.NONE,
            help="The script to run when the key is pressed",
            nargs="?",
        ),
    }
    LOCAL = True

    def run(self, manager, args):
        if args.key is None:
            for key, binding in manager.config.bindings.items():
                console.print(f" [cyan]{key}[/cyan] = [yellow]{repr(binding)}[/yellow]")
        elif args.key is not None and args.script is None:
            if args.key in manager.config.bindings:
                del manager.config.bindings[args.key]
        else:
            manager.config.bindings[args.key] = args.script
