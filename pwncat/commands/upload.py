#!/usr/bin/env python3
import os
import time

from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    DownloadColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

import pwncat
from pwncat.util import console, copyfileobj, human_readable_size, human_readable_delta
from pwncat.commands import Complete, Parameter, ParseType, CommandDefinition


class Command(CommandDefinition):
    """Upload a file from the local host to the remote host"""

    PROG = "upload"
    ARGS = {
        "source": Parameter(Complete.LOCAL_FILE, parser=ParseType.LOCAL_FILE),
        "destination": Parameter(
            Complete.REMOTE_FILE,
            nargs="?",
            parser=ParseType.REMOTE_FILE
        ),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

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
            args.destination = f"./{os.path.basename(args.source)}"

        try:
            length = os.path.getsize(args.source)
            started = time.time()
            with progress:
                task_id = progress.add_task(
                    "upload", filename=args.destination, total=length, start=False
                )

                with open(args.source, "rb") as source:
                    with manager.target.platform.open(
                        args.destination, "wb"
                    ) as destination:
                        progress.start_task(task_id)
                        copyfileobj(
                            source,
                            destination,
                            lambda count: progress.update(task_id, advance=count),
                        )
                        progress.update(task_id, filename="draining buffers...")
                        progress.stop_task(task_id)

                    progress.start_task(task_id)
                    progress.update(task_id, filename=args.destination)

            elapsed = time.time() - started
            console.log(
                f"uploaded [cyan]{human_readable_size(length)}[/cyan] "
                f"in [green]{human_readable_delta(elapsed)}[/green]"
            )
        except (FileNotFoundError, PermissionError, IsADirectoryError) as exc:
            self.parser.error(str(exc))
