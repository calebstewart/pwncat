#!/usr/bin/env python3
import pwncat
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreConstOnce,
    StoreForAction,
    RemoteFileType,
)
from functools import partial
from colorama import Fore
from pwncat import util
from pwncat.util import console
import argparse
import datetime
import time
import os

from rich.progress import (
    BarColumn,
    DownloadColumn,
    TextColumn,
    TransferSpeedColumn,
    TimeRemainingColumn,
    Progress,
    TaskID,
)


class Command(CommandDefinition):
    """ Download a file from the remote host to the local host"""

    PROG = "download"
    ARGS = {
        "source": Parameter(Complete.REMOTE_FILE),
        "destination": Parameter(Complete.LOCAL_FILE, nargs="?"),
    }

    def run(self, args):

        # Create a progress bar for the download
        progress = Progress(
            TextColumn("[bold cyan]{task.fields[filename]}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
        )

        if not args.destination:
            args.destination = os.path.basename(args.source)
        elif os.path.isdir(args.destination):
            args.destination = os.path.join(
                args.destination, os.path.basename(args.source)
            )

        try:
            length = pwncat.victim.get_file_size(args.source)
            started = time.time()
            with progress:
                task_id = progress.add_task(
                    "download", filename=args.source, total=length, start=False
                )
                with open(args.destination, "wb") as destination:
                    with pwncat.victim.open(args.source, "rb", length=length) as source:
                        progress.start_task(task_id)
                        util.copyfileobj(
                            source,
                            destination,
                            lambda count: progress.update(task_id, advance=count),
                        )
                elapsed = time.time() - started

            console.log(
                f"downloaded [cyan]{util.human_readable_size(length)}[/cyan] "
                f"in [green]{util.human_readable_delta(elapsed)}[/green]"
            )
        except (FileNotFoundError, PermissionError, IsADirectoryError) as exc:
            self.parser.error(str(exc))
