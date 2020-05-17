#!/usr/bin/env python3
import pwncat
from pwncat import util
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    parameter,
    StoreConstOnce,
    StoreForAction,
)
from pwncat.tamper import RevertFailed


class Command(CommandDefinition):
    """ View and revert any logged tampers which pwncat has performed on the remote system. """

    PROG = "tamper"
    ARGS = {
        "--tamper,-t": parameter(
            Complete.NONE,
            action=StoreForAction(["revert"]),
            type=int,
            help="Tamper ID to revert (IDs found in tamper list)",
        ),
        "--revert,-r": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="revert",
            help="Revert the selected tamper",
        ),
        "--list,-l": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="list",
            help="List all tampers currently logged by pwncat",
        ),
    }

    def run(self, args):

        if args.action == "revert":
            if args.tamper not in range(len(pwncat.victim.tamper.tampers)):
                self.parser.error("invalid tamper id")
            tamper = pwncat.victim.tamper.tampers[args.tamper]
            try:
                tamper.revert()
                pwncat.victim.tamper.tampers.pop(args.tamper)
            except RevertFailed as exc:
                util.error(f"revert failed: {exc}")
        else:
            for id, tamper in enumerate(pwncat.victim.tamper.tampers):
                print(f" {id} - {tamper}")
