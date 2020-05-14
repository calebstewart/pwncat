#!/usr/bin/env python3
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    parameter,
    StoreConstOnce,
    StoreForAction,
    RemoteFileType,
)
from functools import partial
from colorama import Fore
from pwncat import util
import argparse
import datetime
import time
import os


class Command(CommandDefinition):
    """ Download a file from the remote host to the local host"""

    PROG = "download"
    ARGS = {
        "source": parameter(Complete.REMOTE_FILE),
        "destination": parameter(Complete.LOCAL_FILE),
    }

    def run(self, args):

        try:
            length = self.pty.get_file_size(args.source)
            started = time.time()
            with open(args.destination, "wb") as destination:
                with self.pty.open(args.source, "rb", length=length) as source:
                    util.with_progress(
                        [
                            ("", "downloading "),
                            ("fg:ansigreen", args.source),
                            ("", " to "),
                            ("fg:ansired", args.destination),
                        ],
                        partial(util.copyfileobj, source, destination),
                        length=length,
                    )
            elapsed = time.time() - started
            util.success(
                f"downloaded {Fore.CYAN}{util.human_readable_size(length)}{Fore.RESET} "
                f"in {Fore.GREEN}{util.human_readable_delta(elapsed)}{Fore.RESET}"
            )
        except (FileNotFoundError, PermissionError, IsADirectoryError) as exc:
            self.parser.error(str(exc))
