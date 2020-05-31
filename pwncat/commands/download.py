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
import argparse
import datetime
import time
import os


class Command(CommandDefinition):
    """ Download a file from the remote host to the local host"""

    PROG = "download"
    ARGS = {
        "source": Parameter(Complete.REMOTE_FILE),
        "destination": Parameter(Complete.LOCAL_FILE),
    }

    def run(self, args):

        try:
            length = pwncat.victim.get_file_size(args.source)
            started = time.time()
            with open(args.destination, "wb") as destination:
                with pwncat.victim.open(args.source, "rb", length=length) as source:
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
