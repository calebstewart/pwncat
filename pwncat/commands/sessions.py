#!/usr/bin/env python3
from rich import box
from rich.table import Table

import pwncat
from pwncat.util import console
from pwncat.commands import Complete, Parameter, CommandDefinition


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

            table.add_column("")
            table.add_column("User")
            table.add_column("Host ID")
            table.add_column("Platform")
            table.add_column("Type")
            table.add_column("Address")

            for ident, session in enumerate(manager.sessions):
                ident = str(ident)
                kwargs = {"style": ""}
                if session is manager.target:
                    ident = "*" + ident
                    kwargs["style"] = "underline"
                table.add_row(
                    str(ident),
                    session.current_user().name,
                    str(session.hash),
                    session.platform.name,
                    str(type(session.platform.channel).__name__),
                    str(session.platform.channel),
                    **kwargs,
                )

            console.print(table)

            return

        if args.session_id is None:
            console.log("[red]error[/red]: no session id specified")
            return

        if args.session_id < 0 or args.session_id >= len(manager.sessions):
            console.log(f"[red]error[/red]: {args.session_id}: no such session!")
            return

        session = manager.sessions[args.session_id]

        if args.kill:
            channel = str(session.platform.channel)
            session.close()
            console.log(f"session-{args.session_id} ({channel}) closed")
            return

        manager.target = session
        console.log(f"targeting session-{args.session_id} ({session.platform.channel})")
