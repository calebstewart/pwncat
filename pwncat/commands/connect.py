#!/usr/bin/env python3
from colorama import Fore
import ipaddress
import os.path
import socket
import re

import paramiko
from prompt_toolkit import prompt
from rich.progress import Progress, BarColumn

import pwncat
from pwncat.util import console
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreForAction,
    StoreConstOnce,
)

from pwncat.modules import PersistError
from pwncat.db import get_session


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
            help="List all known hosts and their installed persistence",
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
        r"""^(?P<protocol>[-a-zA-Z0-9_]*://)?((?P<user>[^:@]*)?(?P<password>:(\\@|[^@])*)?@)?(?P<host>[^:]*)?(?P<port>:[0-9]*)?$"""
    )

    def run(self, manager: "pwncat.manager.Manager", args):

        protocol = None
        user = None
        password = None
        host = None
        port = None
        try_reconnect = False

        if args.list:
            # Grab a list of installed persistence methods for all hosts
            # persist.gather will retrieve entries for all hosts if no
            # host is currently connected.
            modules = list(pwncat.modules.run("persist.gather"))
            # Create a mapping of host hash to host object and array of
            # persistence methods
            hosts = {
                host.hash: (host, [])
                for host in get_session().query(pwncat.db.Host).all()
            }

            for module in modules:
                hosts[module.persist.host.hash][1].append(module)

            for host_hash, (host, modules) in hosts.items():
                console.print(
                    f"[magenta]{host.ip}[/magenta] - "
                    f"[red]{host.distro}[/red] - "
                    f"[yellow]{host_hash}[/yellow]"
                )
                for module in modules:
                    console.print(f"  - {str(module)}")

            return

        if args.connection_string:
            m = self.CONNECTION_PATTERN.match(args.connection_string)
            protocol = m.group("protocol")
            user = m.group("user")
            password = m.group("password")
            host = m.group("host")
            port = m.group("port")

        if protocol is not None and args.listen:
            console.log(
                f"[red]error[/red]: --listen is not compatible with an explicit connection string"
            )
            return

        if (
            sum([port is not None, args.port is not None, args.pos_port is not None])
            > 1
        ):
            console.log(f"[red]error[/red]: multiple ports specified")
            return

        if args.port is not None:
            port = args.port
        if args.pos_port is not None:
            port = args.pos_port

        if port is not None:
            try:
                port = int(port.lstrip(":"))
            except:
                console.log(f"[red]error[/red]: {port}: invalid port number")
                return

        if protocol != "ssh://" and args.identity is not None:
            console.log(f"[red]error[/red]: --identity is only valid for ssh protocols")
            return

        manager.create_session(
            platform=args.platform,
            protocol=protocol,
            user=user,
            password=password,
            host=host,
            port=port,
            identity=args.identity,
        )
