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
    parser.add_argument("--ssl", action="store_true", help="Connect or listen with SSL")
    parser.add_argument(
        "--ssl-cert",
        default=None,
        help="Certificate for SSL-encrypted listeners (PEM)",
    )
    parser.add_argument(
        "--ssl-key",
        default=None,
        help="Key for SSL-encrypted listeners (PEM)",
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
        print(importlib.metadata.version("pwncat-cs"))
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
            query_args = {}
            query_args["protocol"] = None
            query_args["user"] = None
            query_args["password"] = None
            query_args["host"] = None
            query_args["port"] = None
            query_args["platform"] = args.platform
            query_args["identity"] = args.identity
            query_args["certfile"] = args.ssl_cert
            query_args["keyfile"] = args.ssl_key
            query_args["ssl"] = args.ssl
            querystring = None

            if args.connection_string:
                m = connect.Command.CONNECTION_PATTERN.match(args.connection_string)
                query_args["protocol"] = m.group("protocol")
                query_args["user"] = m.group("user")
                query_args["password"] = m.group("password")
                query_args["host"] = m.group("host")
                query_args["port"] = m.group("port")
                querystring = m.group("querystring")

                if query_args["protocol"] is not None:
                    query_args["protocol"] = query_args["protocol"].removesuffix("://")

                if query_args["password"] is not None:
                    query_args["password"] = query_args["password"].removeprefix(":")

            if querystring is not None:
                for arg in querystring.split("&"):
                    if arg.find("=") == -1:
                        continue

                    key, *value = arg.split("=")

                    if key in query_args and query_args[key] is not None:
                        console.log(f"[red]error[/red]: multiple values for {key}")
                        return

                    query_args[key] = "=".join(value)

            if query_args["host"] is not None and query_args["host"] == "":
                query_args["host"] = None

            if query_args["protocol"] is not None and args.listen:
                console.log(
                    "[red]error[/red]: --listen is not compatible with an explicit connection string"
                )
                return
            elif args.listen:
                query_args["protocol"] = "bind"

            if (
                query_args["certfile"] is None and query_args["keyfile"] is not None
            ) or (query_args["certfile"] is not None and query_args["keyfile"] is None):
                console.log(
                    "[red]error[/red]: both a ssl certificate and key file are required"
                )
                return

            if query_args["certfile"] is not None or query_args["keyfile"] is not None:
                query_args["ssl"] = True

            if query_args["protocol"] is not None and args.ssl:
                console.log(
                    "[red]error[/red]: --ssl is incompatible with an explicit protocol"
                )
                return

            if (
                sum(
                    [
                        query_args["port"] is not None,
                        args.port is not None,
                        args.pos_port is not None,
                    ]
                )
                > 1
            ):
                console.log("[red]error[/red]: multiple ports specified")
                return

            if args.port is not None:
                query_args["port"] = args.port
            if args.pos_port is not None:
                query_args["port"] = args.pos_port

            if query_args["port"] is not None:
                try:
                    query_args["port"] = int(query_args["port"].lstrip(":"))
                except ValueError:
                    console.log(
                        f"[red]error[/red]: {query_args['port'].lstrip(':')}: invalid port number"
                    )
                    return

            # Attempt to reconnect via installed implants
            if (
                query_args["protocol"] is None
                and query_args["password"] is None
                and query_args["port"] is None
                and args.identity is None
            ):
                db = manager.db.open()
                implants = []

                # Locate all installed implants
                for target in db.root.targets:

                    if (
                        target.guid != query_args["host"]
                        and target.public_address[0] != query_args["host"]
                    ):
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
                        # Check correct query_args["user"]
                        if (
                            query_args["user"] is not None
                            and implant_user.name != query_args["user"]
                        ):
                            continue
                        # Check correct platform
                        if (
                            query_args["platform"] is not None
                            and target.platform != query_args["platform"]
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
                        **query_args,
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
