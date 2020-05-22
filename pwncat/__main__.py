#!/usr/bin/env python3
import argparse
import logging
import selectors
import shlex
import sys

from sqlalchemy.exc import InvalidRequestError

import pwncat
from pwncat import util
from pwncat.remote import Victim


def main():

    # Default log-level is "INFO"
    logging.getLogger().setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="pwncat",
        description="""
    A "living of the land"-based C2 platform.
    
    Aside from the "--config" argument, all other arguments are treated as a pwncat
    command which is parsed after parsing the configuration script.
    """,
    )
    parser.add_argument(
        "--config", "-c", help="A configuration script to execute after loading"
    )
    args, rest = parser.parse_known_args()

    # Build the victim object
    pwncat.victim = Victim(args.config)

    # Run the configuration script
    if args.config:
        with open(args.config, "r") as filp:
            config_script = filp.read()
        pwncat.victim.command_parser.eval(config_script, args.config)

    # Run any remaining command line arguments as one command
    if rest:
        pwncat.victim.command_parser.dispatch_line(shlex.join(rest))

    # if no connection was established in the configuration,
    # drop to the pwncat prompt. Don't allow raw access until
    # a connection is made.
    if not pwncat.victim.connected:
        util.warn("no connection established, entering command mode")
        pwncat.victim.state = util.State.COMMAND
    if not pwncat.victim.connected:
        util.error("no connection established. exiting.")
        exit(0)

    # Setup the selector to wait for data asynchronously from both streams
    selector = selectors.DefaultSelector()
    selector.register(sys.stdin, selectors.EVENT_READ, None)
    selector.register(pwncat.victim.client, selectors.EVENT_READ, "read")

    # Initialize our state
    done = False

    try:
        while not done:
            for k, _ in selector.select():
                if k.fileobj is sys.stdin:
                    data = sys.stdin.buffer.read(8)
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
        util.warn("connection reset by remote host")
    except SystemExit:
        util.success("closing down connection.")
    finally:
        # Restore the shell
        pwncat.victim.restore_local_term()
        try:
            # Make sure everything was committed
            pwncat.victim.session.commit()
        except InvalidRequestError:
            pass
        util.success("local terminal restored")


if __name__ == "__main__":
    main()
    sys.exit(0)
