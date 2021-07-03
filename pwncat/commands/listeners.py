#!/usr/bin/env python3
from rich import box
from rich.table import Table
from rich.prompt import Prompt

import pwncat
from pwncat.util import console
from pwncat.manager import Listener, ListenerError, ListenerState
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Manage active or stopped background listeners. This command
    is only used to interact with established listeners. For
    creating new listeners, use the "listen" command instead.
    """

    PROG = "listeners"
    ARGS = {
        "--all,-a": Parameter(
            Complete.NONE,
            action="store_true",
            help="Show all listeners when listing (default: hide stopped)",
        ),
        "--kill,-k": Parameter(
            Complete.NONE, action="store_true", help="Stop the given listener"
        ),
        "--init,-i": Parameter(
            Complete.NONE, action="store_true", help="Initialize pending channels"
        ),
        "id": Parameter(
            Complete.NONE,
            type=int,
            nargs="?",
            help="The specific listener to interact with",
        ),
    }
    LOCAL = True

    def _init_channel(self, manager: pwncat.manager.Manager, listener: Listener):
        """Initialize pending channel"""

        # Grab list of pending channels
        channels = list(listener.iter_channels())
        if not channels:
            manager.log("no pending channels")
            return

        manager.print(f"Pending Channels for {listener}:")
        for ident, channel in enumerate(channels):
            manager.print(f"{ident}. {channel}")

        manager.print("\nPress C-c to stop initializing channels.")

        platform = "linux"

        try:
            while True:
                if not any(chan is not None for chan in channels):
                    manager.log("all pending channels configured")
                    break

                ident = int(
                    Prompt.ask(
                        "Channel Index",
                        choices=[
                            str(x)
                            for x in range(len(channels))
                            if channels[x] is not None
                        ],
                    )
                )
                if channels[ident] is None:
                    manager.print("[red]error[/red]: channel already initialized.")
                    continue

                platform = Prompt.ask(
                    "Platform Name",
                    default=platform,
                    choices=["linux", "windows", "drop"],
                    show_default=True,
                )

                if platform == "drop":
                    manager.log(f"dropping channel: {channels[ident]}")
                    channels[ident].close()
                    channels[ident] = None
                    continue

                try:
                    listener.bootstrap_session(channels[ident], platform)
                    channels[ident] = None
                except ListenerError as exc:
                    manager.log(f"channel bootstrap failed: {exc}")
                    channels[ident].close()
                    channels[ident] = None
        except KeyboardInterrupt:
            manager.print("")
            pass
        finally:
            for channel in channels:
                if channel is not None:
                    listener.bootstrap_session(channel, platform=None)

    def _show_listener(self, manager: pwncat.manager.Manager, listener: Listener):
        """Show detailed information on a listener"""

        # Makes printing the variables a little more straightforward
        def dump_var(name, value):
            manager.print(f"[yellow]{name}[/yellow] = {value}")

        # Dump common state
        dump_var("address", str(listener))

        state_color = "green"
        if listener.state is ListenerState.FAILED:
            state_color = "red"
        elif listener.state is ListenerState.STOPPED:
            state_color = "yellow"

        dump_var(
            "state",
            f"[{state_color}]"
            + str(listener.state).split(".")[1]
            + f"[/{state_color}]",
        )

        # If the listener failed, show the failure message
        if listener.state is ListenerState.FAILED:
            dump_var("[red]error[/red]", repr(str(listener.failure_exception)))

        dump_var("protocol", repr(listener.protocol))
        dump_var("platform", repr(listener.platform))

        # A count of None means infinity, annotate that
        if listener.count is not None:
            dump_var("remaining", listener.count)
        else:
            dump_var("remaining", "[red]infinite[/red]")

        # Number of pending channels
        dump_var("pending", listener.pending)

        # SSL settings
        dump_var("ssl", repr(listener.ssl))
        if listener.ssl:
            dump_var("ssl_cert", repr(listener.ssl_cert))
            dump_var("ssl_key", repr(listener.ssl_key))

    def run(self, manager: "pwncat.manager.Manager", args):

        if (args.kill or args.init) and args.id is None:
            self.parser.error("missing argument: id")

        if args.kill and args.init:
            self.parser.error("cannot use both kill and init arguments")

        if args.id is not None and (args.id < 0 or args.id >= len(manager.listeners)):
            self.parser.error(f"invalid listener id: {args.id}")

        if args.kill:
            # Kill the specified listener
            with console.status("stopping listener..."):
                manager.listeners[args.id].stop()
            manager.log(f"stopped listener on {str(manager.listeners[args.id])}")
            return

        if args.init:
            self._init_channel(manager, manager.listeners[args.id])
            return

        if args.id is not None:
            self._show_listener(manager, manager.listeners[args.id])
            return

        table = Table(
            "ID",
            "State",
            "Address",
            "Platform",
            "Remaining",
            "Pending",
            title="Listeners",
            box=box.MINIMAL_DOUBLE_HEAD,
        )

        for ident, listener in enumerate(manager.listeners):

            if listener.state is ListenerState.STOPPED and not args.all:
                continue

            if listener.count is None:
                count = "[red]inf[/red]"
            else:
                count = str(listener.count)

            table.add_row(
                str(ident),
                str(listener.state).split(".")[1],
                f"[blue]{listener.address[0]}[/blue]:[cyan]{listener.address[1]}[/cyan]",
                str(listener.platform),
                count,
                str(listener.pending),
            )

        console.print(table)
