#!/usr/bin/env python3
from rich.table import Table
from rich import box

import pwncat
from pwncat.util import console
from pwncat.commands.base import CommandDefinition, Complete, Parameter


class Command(CommandDefinition):
    """
    Interact and control active remote sessions. This command can be used
    to change context between sessions or kill active sessions which were
    established with the `connect` command.
    """

    PROG = "sessions"
    ARGS = {
        "--list,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="List active connections",
        ),
        "--kill,-k": Parameter(
            Complete.NONE,
            action="store_true",
            help="Kill an active session",
        ),
        "session_id": Parameter(
            Complete.NONE,
            type=int,
            help="Interact with the given session",
            nargs="?",
        ),
    }
    LOCAL = True

    def run(self, manager: "pwncat.manager.Manager", args):

        if args.list or (not args.kill and args.session_id is None):
            table = Table(title="Active Sessions", box=box.MINIMAL_DOUBLE_HEAD)

            table.add_column("Active")
            table.add_column("ID")
            table.add_column("Platform")
            table.add_column("Type")
            table.add_column("Address")

            for session in manager.sessions:
                table.add_row(
                    str(session == manager.target),
                    str(session.host),
                    session.platform.name,
                    str(type(session.platform.channel).__name__),
                    str(session.platform.channel),
                )

            console.print(table)

            return

        if args.session_id is None:
            console.log("[red]error[/red]: no session id specified")
            return

        session = None
        for s in manager.sessions:
            if s.host == args.session_id:
                session = s
                break
        else:
            console.log(f"[red]error[/red]: {args.session_id}: no such active session")
            return

        if args.kill:
            session.platform.channel.close()
            session.died()
            console.log(f"session {session.host} closed")
            return

        manager.target = session
        console.log(f"targeting session {session.host}")
