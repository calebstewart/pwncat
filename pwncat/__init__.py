#!/usr/bin/env python3
import os
import sys
import selectors
from io import TextIOWrapper
from typing import Optional

from sqlalchemy.exc import InvalidRequestError

# These need to be assigned prior to importing other
# parts of pwncat
victim: Optional["pwncat.remote.Victim"] = None

from .util import console
from .config import Config
from .tamper import TamperManager
from .commands import parser

tamper: TamperManager = TamperManager()


def interactive(platform):
    """Run the interactive pwncat shell with the given initialized victim.
    This function handles the pwncat and remote prompts and does not return
    until explicitly exited by the user.

    This doesn't work yet. It's dependant on the new platform and channel
    interface that isn't working yet, but it's what I'd like the eventual
    interface to look like.

    :param platform: an initialized platform object with a valid channel
    :type platform: pwncat.platform.Platform
    """

    global victim
    global config

    # Initialize a new victim
    victim = platform

    # Ensure the prompt is initialized
    parser.setup_prompt()

    # Ensure our stdin reference is unbuffered
    sys.stdin = TextIOWrapper(
        os.fdopen(sys.stdin.fileno(), "br", buffering=0),
        write_through=True,
        line_buffering=False,
    )

    # Ensure we are in raw mode
    parser.raw_mode()

    # Create selector for asynchronous IO
    selector = selectors.DefaultSelector()
    selector.register(sys.stdin, selectors.EVENT_READ, None)
    selector.register(victim.channel, selectors.EVENT_READ, None)

    # Main loop state
    done = False

    try:
        while not done:

            for key, _ in selector.select():
                if key.fileobj is sys.stdin:
                    data = sys.stdin.buffer.read(64)
                    data = parser.parse_prefix(data)
                    if data:
                        victim.channel.send(data)
                else:
                    data = victim.channel.recv(4096)
                    if data is None or not data:
                        done = True
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.flush()
    except ConnectionResetError:
        console.log("[yellow]warning[/yellow]: connection reset by remote host")
    except SystemExit:
        console.log("closing connection")
    finally:
        # Ensure the terminal is back to normal
        parser.restore_term()
        try:
            # Commit any pending changes to the database
            get_session().commit()
        except InvalidRequestError:
            pass
