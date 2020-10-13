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

# from pwncat.persist import PersistenceError
from pwncat.modules.persist import PersistError
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
        "--config,-c": Parameter(
            Complete.LOCAL_FILE,
            help="Path to a configuration script to execute prior to connecting",
        ),
        "--identity,-i": Parameter(
            Complete.LOCAL_FILE,
            help="The private key for authentication for SSH connections",
        ),
        "--listen,-l": Parameter(
            Complete.NONE,
            action="store_true",
            help="Enable the `bind` protocol (supports netcat-like syntax)",
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

    def run(self, args):

        protocol = None
        user = None
        password = None
        host = None
        port = None
        try_reconnect = False

        if not args.config and os.path.exists("./pwncatrc"):
            args.config = "./pwncatrc"
        elif not args.config and os.path.exists("./data/pwncatrc"):
            args.config = "./data/pwncatrc"

        if args.config:
            try:
                # Load the configuration
                with open(args.config, "r") as filp:
                    pwncat.parser.eval(filp.read(), args.config)
            except OSError as exc:
                console.log(f"[red]error[/red]: {exc}")
                return

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

        # Attempt to assume a protocol based on context
        if protocol is None:
            if args.listen:
                protocol = "bind://"
            elif args.port is not None:
                protocol = "connect://"
            elif user is not None:
                protocol = "ssh://"
                try_reconnect = True
            elif host == "" or host == "0.0.0.0":
                protocol = "bind://"
            elif args.connection_string is None:
                self.parser.print_help()
                return
            else:
                protocol = "connect://"
                try_reconnect = True

        if protocol != "ssh://" and args.identity is not None:
            console.log(f"[red]error[/red]: --identity is only valid for ssh protocols")
            return

        if pwncat.victim.client is not None:
            console.log("connection [red]already active[/red]")
            return

        if protocol == "reconnect://" or try_reconnect:
            level = "[yellow]warning[/yellow]" if try_reconnect else "[red]error[/red]"

            try:
                addr = ipaddress.ip_address(socket.gethostbyname(host))
                row = (
                    get_session().query(pwncat.db.Host).filter_by(ip=str(addr)).first()
                )
                if row is None:
                    console.log(f"{level}: {str(addr)}: not found in database")
                    host_hash = None
                else:
                    host_hash = row.hash
            except ValueError:
                host_hash = host

            # Reconnect to the given host
            if host_hash is not None:
                try:
                    pwncat.victim.reconnect(host_hash, password, user)
                    return
                except Exception as exc:
                    console.log(f"{level}: {host}: {exc}")

        if protocol == "reconnect://" and not try_reconnect:
            # This means reconnection failed, and we had an explicit
            # reconnect protocol
            return

        if protocol == "bind://":
            if not host or host == "":
                host = "0.0.0.0"

            if port is None:
                console.log(f"[red]error[/red]: no port specified")
                return

            with Progress(
                f"bound to [blue]{host}[/blue]:[cyan]{port}[/cyan]",
                BarColumn(bar_width=None),
                transient=True,
            ) as progress:
                task_id = progress.add_task("listening", total=1, start=False)
                # Create the socket server
                server = socket.create_server((host, port), reuse_port=True)

                try:
                    # Wait for a connection
                    (client, address) = server.accept()
                except KeyboardInterrupt:
                    progress.update(task_id, visible=False)
                    progress.log("[red]aborting[/red] listener")
                    return

                progress.update(task_id, visible=False)
                progress.log(
                    f"[green]received[/green] connection from [blue]{address[0]}[/blue]:[cyan]{address[1]}[/cyan]"
                )

            pwncat.victim.connect(client)
        elif protocol == "connect://":
            if not host:
                console.log("[red]error[/red]: no host address provided")
                return

            if port is None:
                console.log(f"[red]error[/red]: no port specified")
                return

            with Progress(
                f"connecting to [blue]{host}[/blue]:[cyan]{port}[/cyan]",
                BarColumn(bar_width=None),
                transient=True,
            ) as progress:
                task_id = progress.add_task("connecting", total=1, start=False)
                # Connect to the remote host
                client = socket.create_connection((host, port))

                progress.update(task_id, visible=False)
                progress.log(
                    f"connection to "
                    f"[blue]{host}[/blue]:[cyan]{port}[/cyan] [green]established[/green]"
                )

            pwncat.victim.connect(client)
        elif protocol == "ssh://":

            if port is None:
                port = 22

            if not user or user is None:
                self.parser.error("you must specify a user")

            if not (password or args.identity):
                password = prompt("Password: ", is_password=True)

            try:
                # Connect to the remote host's ssh server
                sock = socket.create_connection((host, port))
            except Exception as exc:
                console.log(f"[red]error[/red]: {str(exc)}")
                return

            # Create a paramiko SSH transport layer around the socket
            t = paramiko.Transport(sock)
            try:
                t.start_client()
            except paramiko.SSHException:
                sock.close()
                console.log("[red]error[/red]: ssh negotiation failed")
                return

            if args.identity:
                try:
                    # Load the private key for the user
                    key = paramiko.RSAKey.from_private_key_file(args.identity)
                except:
                    password = prompt("RSA Private Key Passphrase: ", is_password=True)
                    key = paramiko.RSAKey.from_private_key_file(args.identity, password)

                # Attempt authentication
                try:
                    t.auth_publickey(user, key)
                except paramiko.ssh_exception.AuthenticationException as exc:
                    console.log(f"[red]error[/red]: authentication failed: {exc}")
            else:
                try:
                    t.auth_password(user, password)
                except paramiko.ssh_exception.AuthenticationException as exc:
                    console.log(f"[red]error[/red]: authentication failed: {exc}")

            if not t.is_authenticated():
                t.close()
                sock.close()
                return

            # Open an interactive session
            chan = t.open_session()
            chan.get_pty()
            chan.invoke_shell()

            # Initialize the session!
            pwncat.victim.connect(chan)
        else:
            console.log(f"[red]error[/red]: {args.action}: invalid action")
