#!/usr/bin/env python3
from io import TextIOWrapper
import logging
import selectors
import shlex
import sys
import warnings
import os
from pathlib import Path
import inspect

from sqlalchemy import exc as sa_exc
from sqlalchemy.exc import InvalidRequestError
from paramiko.buffered_pipe import BufferedPipe

import pwncat
from pwncat.util import console
from pwncat.remote import Victim


def main():

    params = inspect.signature(BufferedPipe.read).parameters

    if "flags" not in params:
        console.log(
            f"[red]error[/red]: pwncat requires a custom fork of paramiko. This can be installed with `pip install -U git+https://github.com/calebstewart/paramiko`"
        )
        sys.exit(1)

    # Ignore SQL Alchemy warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=sa_exc.SAWarning)

        # Default log-level is "INFO"
        logging.getLogger().setLevel(logging.INFO)

        # Build the victim object
        pwncat.victim = Victim()

        # Find the user configuration
        config_path = (
            Path(os.environ.get("XDG_CONFIG_HOME", "~/.config/"))
            / "pwncat"
            / "pwncatrc"
        )
        config_path = config_path.expanduser()

        try:
            # Read the config script
            with config_path.open("r") as filp:
                script = filp.read()

            # Run the script
            pwncat.victim.command_parser.eval(script, str(config_path))
        except (FileNotFoundError, PermissionError):
            # The config doesn't exist
            pass

        # Arguments to `pwncat` are considered arguments to `connect`
        # We use the `prog_name` argument to make the help for "connect"
        # display "pwncat" in the usage. This is just a visual fix, and
        # isn't used anywhere else.
        pwncat.victim.command_parser.dispatch_line(
            shlex.join(["connect"] + sys.argv[1:]), prog_name="pwncat"
        )

        # Only continue if we successfully connected
        if not pwncat.victim.connected:
            sys.exit(0)

        # Make stdin unbuffered. Without doing this, some key sequences
        # which are multi-byte don't get sent properly (e.g. up and left
        # arrow keys)
        sys.stdin = TextIOWrapper(
            os.fdopen(sys.stdin.fileno(), "br", buffering=0),
            write_through=True,
            line_buffering=False,
        )

        # Setup the selector to wait for data asynchronously from both streams
        selector = selectors.DefaultSelector()
        selector.register(sys.stdin, selectors.EVENT_READ, None)
        selector.register(pwncat.victim.client, selectors.EVENT_READ, "read")

        # Initialize our state
        done = False

        try:
            # This loop is only used to funnel data between the local
            # and remote hosts when in raw mode. During the `pwncat`
            # prompt, the main loop is handled by the CommandParser
            # class `run` method.
            while not done:
                for k, _ in selector.select():
                    if k.fileobj is sys.stdin:
                        data = sys.stdin.buffer.read(64)
                        pwncat.victim.process_input(data)
                    else:
                        data = pwncat.victim.recv()
                        if data is None or len(data) == 0:
                            done = True
                            break
                        sys.stdout.buffer.write(data)
                        sys.stdout.flush()
        except ConnectionResetError:
            pwncat.victim.restore_local_term()
            console.log("[yellow]warning[/yellow]: connection reset by remote host")
        except SystemExit:
            console.log("closing connection")
        finally:
            # Restore the shell
            pwncat.victim.restore_local_term()
            try:
                # Make sure everything was committed
                pwncat.victim.session.commit()
            except InvalidRequestError:
                pass


if __name__ == "__main__":

    main()

    sys.exit(0)
