#!/usr/bin/env python3

from pwncat.commands.base import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Leave a layer of execution from this session. Layers are normally added
    as sub-shells from escalation modules.
    """

    PROG = "leave"
    ARGS = {
        "count": Parameter(
            Complete.NONE,
            type=int,
            default=1,
            nargs="?",
            help="number of layers to remove (default: 1)",
        ),
        "--all,-a": Parameter(
            Complete.NONE,
            action="store_true",
            help="leave all active layers",
        ),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        try:
            if args.all:
                args.count = len(manager.target.layers)

            for i in range(args.count):
                manager.target.layers.pop()(manager.target)
        except IndexError:
            manager.target.log("[yellow]warning[/yellow]: no more layers to leave")
