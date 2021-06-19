#!/usr/bin/env python3
from rich.prompt import Confirm

import pwncat
from pwncat.util import console
from pwncat.manager import ListenerState
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Create a new background listener. Background listeners will continue
    listening while you do other things in pwncat. When a connection is
    established, the listener will either queue the new channel for
    future initialization or construct a full session.

    If a platform is provided, a session will automatically be established
    for any new incoming connections. If no platform is provided, the
    channels will be queued, and can be initialized with the 'listeners'
    command.

    If the drop_duplicate option is provided, sessions which connect to
    a host which already has an active session with the same user will
    be automatically dropped. This facilitates an infinite callback implant
    which you don't want to pollute the active session list.
    """

    PROG = "listen"
    ARGS = {
        "--count,-c": Parameter(
            Complete.NONE,
            type=int,
            help="Number of sessions a listener should accept before automatically stopping (default: infinite)",
        ),
        "--platform,-m": Parameter(
            Complete.NONE,
            type=str,
            help="Name of the platform used to automatically construct a session for a new connection",
        ),
        "--ssl": Parameter(
            Complete.NONE,
            action="store_true",
            default=False,
            help="Wrap a new listener in an SSL context",
        ),
        "--ssl-cert": Parameter(
            Complete.LOCAL_FILE,
            help="SSL Server Certificate for SSL wrapped listeners",
        ),
        "--ssl-key": Parameter(
            Complete.LOCAL_FILE,
            help="SSL Server Private Key for SSL wrapped listeners",
        ),
        "--host,-H": Parameter(
            Complete.NONE,
            help="Host address on which to bind (default: 0.0.0.0)",
            default="0.0.0.0",
        ),
        "port": Parameter(
            Complete.NONE,
            type=int,
            help="Port on which to listen for new listeners",
        ),
        "--drop-duplicate,-D": Parameter(
            Complete.NONE,
            action="store_true",
            help="Automatically drop sessions with hosts that are already active",
        ),
    }
    LOCAL = True

    def _drop_duplicate(self, session: "pwncat.manager.Session"):

        for other in session.manager.sessions.values():
            if (
                other is not session
                and session.hash == other.hash
                and session.platform.getuid() == other.platform.getuid()
            ):
                session.log("dropping duplicate session")
                return False

        return True

    def run(self, manager: "pwncat.manager.Manager", args):

        if args.drop_duplicate:
            established = self._drop_duplicate

        if args.platform is None:
            manager.print(
                "You have not specified a platform. Connections will be queued until initialized with the 'listeners' command."
            )
            if not Confirm.ask("Are you sure?"):
                return

        with console.status("creating listener..."):
            listener = manager.create_listener(
                protocol="socket",
                platform=args.platform,
                host=args.host,
                port=args.port,
                ssl=args.ssl,
                ssl_cert=args.ssl_cert,
                ssl_key=args.ssl_key,
                established=established,
                count=args.count,
            )

            while listener.state is ListenerState.STOPPED:
                pass

        if listener.state is ListenerState.FAILED:
            manager.log(
                f"[red]error[/red]: listener startup failed: {listener.failure_exception}"
            )
        else:
            manager.log(f"new listener created for {listener}")
