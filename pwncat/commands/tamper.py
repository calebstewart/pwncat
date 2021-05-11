#!/usr/bin/env python3
from typing import List

from rich.progress import Progress, BarColumn

import pwncat
from pwncat.util import console
from pwncat.tamper import Tamper, RevertFailed
from pwncat.commands.base import (Complete, Parameter, StoreConstOnce,
                                  StoreForAction, CommandDefinition)


class Command(CommandDefinition):
    """ View and revert any logged tampers which pwncat has performed on the remote system. """

    PROG = "tamper"
    ARGS = {
        "--tamper,-t": Parameter(
            Complete.NONE,
            action=StoreForAction(["revert"]),
            type=int,
            help="Tamper ID to revert (IDs found in tamper list)",
        ),
        "--all,-a": Parameter(
            Complete.NONE,
            action="store_true",
            help="Attempt to revert all tampered files",
        ),
        "--revert,-r": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="revert",
            help="Revert the selected tamper",
        ),
        "--list,-l": Parameter(
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
                tampers = list(pwncat.tamper)
            else:
                try:
                    tampers = [pwncat.tamper[args.tamper]]
                except KeyError:
                    console.log("[red]error[/red]: invalid tamper id")
                    return
            self.revert(tampers)
        else:
            for ident, tamper in enumerate(pwncat.tamper):
                console.print(f" [cyan]{ident}[/cyan] - {tamper}")

    def revert(self, tampers: List[Tamper]):
        """ Revert the list of tampers with a nice progress bar """

        with Progress(
            "[bold]reverting[/bold]",
            "•",
            "{task.fields[tamper]}",
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            console=console,
        ) as progress:
            task = progress.add_task("reverting", tamper="init", total=len(tampers))
            for tamper in tampers:
                try:
                    progress.update(task, tamper=str(tamper))
                    tamper.revert()
                    pwncat.tamper.remove(tamper)
                except RevertFailed as exc:
                    progress.log(f"[yellow]warning[/yellow]: revert failed: {exc}")
                progress.update(task, advance=1)
            progress.update(task, tamper="complete")
