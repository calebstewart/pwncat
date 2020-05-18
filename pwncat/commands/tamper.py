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
        "--all,-a": parameter(
            Complete.NONE,
            action="store_true",
            help="Attempt to revert all tampered files",
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
            if args.all:
                removed_tampers = []
                util.progress(f"reverting tamper")
                for tamper in pwncat.victim.tamper:
                    try:
                        util.progress(f"reverting tamper: {tamper}")
                        tamper.revert()
                        removed_tampers.append(tamper)
                    except RevertFailed as exc:
                        util.warn(f"{tamper}: revert failed: {exc}")
                for tamper in removed_tampers:
                    pwncat.victim.tamper.remove(tamper)
                util.success("tampers reverted!")
                pwncat.victim.session.commit()
            else:
                if args.tamper not in range(len(pwncat.victim.tamper)):
                    self.parser.error("invalid tamper id")
                tamper = pwncat.victim.tamper[args.tamper]
                try:
                    tamper.revert()
                    pwncat.victim.tamper.remove(tamper)
                except RevertFailed as exc:
                    util.error(f"revert failed: {exc}")
                pwncat.victim.session.commit()
        else:
            for id, tamper in enumerate(pwncat.victim.tamper):
                print(f" {id} - {tamper}")
