#!/usr/bin/env python3
import os
import time
from functools import partial

from colorama import Fore

import pwncat
from pwncat import util
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    RemoteFileType,
)


class Command(CommandDefinition):
    """ Upload a file from the local host to the remote host"""

    PROG = "upload"
    ARGS = {
        "source": Parameter(Complete.LOCAL_FILE),
        "destination": Parameter(
            Complete.REMOTE_FILE,
            type=("method", RemoteFileType(file_exist=False, directory_exist=True)),
        ),
    }

    def run(self, args):

        try:
            length = os.path.getsize(args.source)
            started = time.time()
            with open(args.source, "rb") as source:
                with pwncat.victim.open(
                    args.destination, "wb", length=length
                ) as destination:
                    util.with_progress(
                        [
                            ("", "uploading "),
                            ("fg:ansigreen", args.source),
                            ("", " to "),
                            ("fg:ansired", args.destination),
                        ],
                        partial(util.copyfileobj, source, destination),
                        length=length,
                    )
            elapsed = time.time() - started
            util.success(
                f"uploaded {Fore.CYAN}{util.human_readable_size(length)}{Fore.RESET} "
                f"in {Fore.GREEN}{util.human_readable_delta(elapsed)}{Fore.RESET}"
            )
        except (FileNotFoundError, PermissionError, IsADirectoryError) as exc:
            self.parser.error(str(exc))
