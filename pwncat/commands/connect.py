#!/usr/bin/env python3
import re

from rich import box
from rich.table import Table
from rich.progress import Progress

import pwncat
from pwncat.util import console
from pwncat.modules import ModuleFailed
from pwncat.commands import Complete, Parameter, CommandDefinition


class Command(CommandDefinition):
    """
    Connect to a remote victim. This command is only valid prior to an established
    connection. This command attempts to act similar to common tools such as netcat
    and ssh simultaneosly. Connection strings come in two forms. Firstly, pwncat
    can act like netcat. Using `connect [host] [port]` will connect to a bind shell,
    while `connect -l [port]` will listen for a reverse shell on the specified port.

    The second form is more explicit. A connection string can be used of the form
    `[protocol://][user[:password]@][host][:port]`. If a user is specified, the
    default protocol is `ssh`. If no user is specified, the default protocol is
    `connect` (connect to bind shell). If no host is specified or `host` is "0.0.0.0"
    then the `bind` protocol is used (listen for reverse shell). The currently available
    protocols are:

    - ssh
    - connect
    - bind

    The `--identity/-i` argument is ignored unless the `ssh` protocol is used.
    """

    PROG = "connect"
    ARGS = {
        "--identity,-i": Parameter(
            Complete.LOCAL_FILE,
            help="The private key for authentication for SSH connections",
        ),
        "--listen,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="Enable the `bind` protocol (supports netcat-like syntax)",
        ),
        "--platform,-m": Parameter(
            Complete.NONE,
            help="Name of the platform to use (default: linux)",
            default="linux",
        ),
        "--port,-p": Parameter(
            Complete.NONE,
            help="Alternative port number argument supporting netcat-like syntax",
        ),
        "--list": Parameter(
            Complete.NONE,
            action="store_true",
            help="List installed implants with remote connection capability",
        ),
        "--certificate,--cert": Parameter(
            Complete.NONE,
            help="Certificate for SSL-encrypted listeners",
        ),
        "connection_string": Parameter(
            Complete.NONE,
            metavar="[protocol://][user[:password]@][host][:port]",
            help="Connection string describing the victim to connect to",
            nargs="?",
        ),
        "pos_port": Parameter(
            Complete.NONE,
            nargs="?",
            metavar="port",
            help="Alternative port number argument supporting netcat-like syntax",
        ),
    }
    LOCAL = True
    CONNECTION_PATTERN = re.compile(
        r"""^(?P<protocol>[-a-zA-Z0-9_]*://)?((?P<user>[^:@]*)?(?P<password>:(\\@|[^@])*)?@)?(?P<host>[^:]*)?(?P<port>:[0-9]*)?(\?(?P<querystring>.*))?$"""
    )

    def run(self, manager: "pwncat.manager.Manager", args):

        query_args = {}
        query_args["protocol"] = None
        query_args["user"] = None
        query_args["password"] = None
        query_args["host"] = None
        query_args["port"] = None
        query_args["platform"] = args.platform
        query_args["identity"] = args.identity
        query_args["certfile"] = args.certificate
        query_args["keyfile"] = args.certificate
        querystring = None
        used_implant = None

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

        if args.connection_string:
            m = self.CONNECTION_PATTERN.match(args.connection_string)
            query_args["protocol"] = m.group("protocol")
            query_args["user"] = m.group("user")
            query_args["password"] = m.group("password")
            query_args["host"] = m.group("host")
            query_args["port"] = m.group("port")
            querystring = m.group("querystring")

            if query_args["protocol"] is not None:
                query_args["protocol"] = query_args["protocol"].removesuffix("://")

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
                    if query_args["user"] is not None and implant_user.name != user:
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

        if used_implant is not None:
            manager.target.log(f"connected via {used_implant.title(manager.target)}")
        else:
            manager.create_session(**query_args)
