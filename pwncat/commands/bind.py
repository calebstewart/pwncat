#!/usr/bin/env python3


from pwncat.util import console
from pwncat.config import KeyType
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Create key aliases for when in raw mode. This only works from platforms
    which provide a raw interaction (such as linux).
    """

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
