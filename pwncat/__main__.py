#!/usr/bin/env python3
import sys
import logging
import argparse
import importlib.metadata

from rich import box
from rich.table import Table
from rich.progress import Progress, SpinnerColumn

import pwncat.manager
from pwncat.util import console
from pwncat.channel import ChannelError
from pwncat.modules import ModuleFailed
from pwncat.commands import connect
from pwncat.platform import PlatformError


def main():

    # Default log-level is "INFO"
    logging.getLogger().setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        description="""Start interactive pwncat session and optionally connect to existing victim via a known platform and channel type. This entrypoint can also be used to list known implants on previous targets."""
    )
    parser.add_argument(
        "--version", "-v", action="store_true", help="Show version number and exit"
    )
    parser.add_argument(
        "--download-plugins",
        action="store_true",
        help="Pre-download all Windows builtin plugins and exit immediately",
    )
    parser.add_argument(
        "--config",
        "-c",
        type=argparse.FileType("r"),
        default=None,
        help="Custom configuration file (default: ./pwncatrc)",
    )
    parser.add_argument(
        "--identity",
        "-i",
        type=argparse.FileType("r"),
        default=None,
        help="Private key for SSH authentication",
    )
    parser.add_argument(
        "--listen",
        "-l",
        action="store_true",
        help="Enable the `bind` protocol (supports netcat-style syntax)",
    )
    parser.add_argument(
        "--platform",
        "-m",
        help="Name of the platform to use (default: linux)",
        default="linux",
    )
    parser.add_argument(
        "--port",
        "-p",
        help="Alternative way to specify port to support netcat-style syntax",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List installed implants with remote connection capability",
    )
    parser.add_argument(
        "connection_string",
        metavar="[protocol://][user[:password]@][host][:port]",
        help="Connection string describing victim",
        nargs="?",
    )
    parser.add_argument(
        "pos_port",
        nargs="?",
        metavar="port",
        help="Alternative port number to support netcat-style syntax",
    )
    parser.add_argument(
        "--verbose",
        "-V",
        action="store_true",
        help="Enable verbose output for the remote commands executed by `pwncat`",
    )
    args = parser.parse_args()

    # Print the version number and exit.
    if args.version:
        print(importlib.metadata.version("pwncat"))
        return

    # Create the session manager
    with pwncat.manager.Manager(args.config) as manager:

        if args.verbose:
            # set the config variable `verbose` to `True` (globally)
            manager.config.set("verbose", True, True)

        if args.download_plugins:
            for plugin_info in pwncat.platform.Windows.PLUGIN_INFO:
                with pwncat.platform.Windows.open_plugin(
                    manager, plugin_info.provides[0]
                ):
                    pass

            return

        if args.list:

            db = manager.db.open()
            implants = []

            table = Table(
                "ID",
                "Address",
                "Platform",
                "Implant",
                "User",
                box=box.MINIMAL_DOUBLE_HEAD,
            )

            # Locate all installed implants
            for target in db.root.targets:

                # Collect users
                users = {}
                for fact in target.facts:
                    if "user" in fact.types:
                        users[fact.id] = fact

                # Collect implants
                for fact in target.facts:
                    if "implant.remote" in fact.types:
                        table.add_row(
                            target.guid,
                            target.public_address[0],
                            target.platform,
                            fact.source,
                            users[fact.uid].name,
                        )

            if not table.rows:
                console.log("[red]error[/red]: no remote implants found")
            else:
                console.print(table)

            return

        console.log("Welcome to [red]pwncat[/red] 🐈!")

        if (
            args.connection_string is not None
            or args.pos_port is not None
            or args.port is not None
            or args.listen
            or args.identity is not None
        ):
            protocol = None
            user = None
            password = None
            host = None
            port = None

            if args.connection_string:
                m = connect.Command.CONNECTION_PATTERN.match(args.connection_string)
                protocol = m.group("protocol")
                user = m.group("user")
                password = m.group("password")
                host = m.group("host")
                port = m.group("port")

                if password is not None:
                    password = password.removeprefix(":")

            if protocol is not None:
                protocol = protocol.removesuffix("://")

            if host is not None and host == "":
                host = None

            if protocol is not None and args.listen:
                console.log(
                    "[red]error[/red]: --listen is not compatible with an explicit connection string"
                )
                return
            elif args.listen:
                protocol = "bind"

            if (
                sum(
                    [
                        port is not None,
                        args.port is not None,
                        args.pos_port is not None,
                    ]
                )
                > 1
            ):
                console.log("[red]error[/red]: multiple ports specified")
                return

            if args.port is not None:
                port = args.port
            if args.pos_port is not None:
                port = args.pos_port

            if port is not None:
                try:
                    port = int(port.lstrip(":"))
                except ValueError:
                    console.log(f"[red]error[/red]: {port}: invalid port number")
                    return

            # Attempt to reconnect via installed implants
            if (
                protocol is None
                and password is None
                and port is None
                and args.identity is None
            ):
                db = manager.db.open()
                implants = []

                # Locate all installed implants
                for target in db.root.targets:

                    if target.guid != host and target.public_address[0] != host:
                        continue

                    # Collect users
                    users = {}
                    for fact in target.facts:
                        if "user" in fact.types:
                            users[fact.id] = fact

                    # Collect implants
                    for fact in target.facts:
                        if "implant.remote" in fact.types:
                            implants.append((target, users[fact.uid], fact))

                with Progress(
                    "triggering implant",
                    "•",
                    "{task.fields[status]}",
                    transient=True,
                    console=console,
                ) as progress:
                    task = progress.add_task("", status="...")
                    for target, implant_user, implant in implants:
                        # Check correct user
                        if user is not None and implant_user.name != user:
                            continue
                        # Check correct platform
                        if (
                            args.platform is not None
                            and target.platform != args.platform
                        ):
                            continue

                        progress.update(
                            task, status=f"trying [cyan]{implant.source}[/cyan]"
                        )

                        # Attempt to trigger a new session
                        try:
                            session = implant.trigger(manager, target)
                            manager.target = session
                            used_implant = implant
                            break
                        except ModuleFailed:
                            db.transaction_manager.commit()
                            continue

            if manager.target is not None:
                manager.target.log(
                    f"connected via {used_implant.title(manager.target)}"
                )
            else:
                try:
                    manager.create_session(
                        platform=args.platform,
                        protocol=protocol,
                        user=user,
                        password=password,
                        host=host,
                        port=port,
                        identity=args.identity,
                    )
                except (ChannelError, PlatformError) as exc:
                    manager.log(f"connection failed: {exc}")
                except KeyboardInterrupt:
                    # hide '^C' from the output
                    sys.stdout.write("\b\b\r")
                    manager.log("[yellow]warning[/yellow]: cancelled by user")

        manager.interactive()

        if manager.sessions:
            with Progress(
                SpinnerColumn(),
                "closing sessions",
                "•",
                "{task.fields[status]}",
                console=console,
                transient=True,
            ) as progress:
                task = progress.add_task("task", status="...")

                # Retrieve the existing session IDs list
                session_ids = list(manager.sessions.keys())

                # Close each session based on its ``session_id``
                for session_id in session_ids:
                    progress.update(
                        task, status=str(manager.sessions[session_id].platform)
                    )
                    manager.sessions[session_id].close()

                progress.update(task, status="done!", completed=100)


if __name__ == "__main__":

    main()

    sys.exit(0)
