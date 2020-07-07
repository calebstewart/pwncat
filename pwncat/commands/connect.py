#!/usr/bin/env python3
from colorama import Fore
import ipaddress
import socket

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
from pwncat.persist import PersistenceError


class Command(CommandDefinition):
    """ Connect to a remote host via SSH, bind/reverse shells or previous
    persistence methods installed during past sessions. """

    PROG = "connect"
    ARGS = {
        "--config,-C": Parameter(
            Complete.NONE,
            help="Path to a configuration script to execute prior to connecting",
        ),
        "--listen,-l": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="listen",
            nargs=0,
            help="Listen for an incoming reverse shell",
        ),
        "--connect,-c": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="connect",
            nargs=0,
            help="Connect to a remote bind shell",
        ),
        "--ssh,-s": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="ssh",
            nargs=0,
            help="Connect to a remote ssh server",
        ),
        "--reconnect,-r": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="reconnect",
            nargs=0,
            help="Reconnect to the given host via a persistence method",
        ),
        "--list": Parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="list",
            nargs=0,
            help="List remote hosts with persistence methods installed",
        ),
        "--host,-H": Parameter(
            Complete.NONE,
            help="Address to listen on or remote host to connect to. For reconnections, this can be a host hash",
        ),
        "--port,-p": Parameter(
            Complete.NONE,
            type=int,
            help="The port to listen on or connect to",
            action=StoreForAction(["connect", "listen", "ssh"]),
        ),
        "--method,-m": Parameter(
            Complete.NONE,
            help="The method to user for reconnection",
            action=StoreForAction(["reconnect"]),
        ),
        "--user,-u": Parameter(
            Complete.NONE,
            help="The user to reconnect as; if this is a system method, this parameter is ignored.",
            action=StoreForAction(["reconnect", "ssh"]),
        ),
        "--password,-P": Parameter(
            Complete.NONE,
            help="The password for the specified user for SSH connections",
            action=StoreForAction(["ssh"]),
        ),
        "--identity,-i": Parameter(
            Complete.NONE,
            help="The private key for authentication for SSH connections",
            action=StoreForAction(["ssh"]),
        ),
    }
    DEFAULTS = {"action": "none"}
    LOCAL = True

    def run(self, args):

        if pwncat.victim.client is not None:
            console.log("connection [red]already active[/red]")
            return

        if args.config:
            try:
                # Load the configuration
                with open(args.config, "r") as filp:
                    pwncat.victim.command_parser.eval(filp.read(), args.config)
            except OSError as exc:
                console.log(f"[red]error[/red]: {exc}")
                return

        if args.action == "none":
            # No action was provided, and no connection was made in the config
            if pwncat.victim.client is None:
                self.parser.print_help()
            return

        if args.action == "listen":
            if not args.host:
                args.host = "0.0.0.0"

            with Progress(
                f"bound to [blue]{args.host}[/blue]:[cyan]{args.port}[/cyan]",
                BarColumn(bar_width=None),
            ) as progress:
                task_id = progress.add_task("listening", total=1, start=False)
                # Create the socket server
                server = socket.create_server((args.host, args.port), reuse_port=True)

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
        elif args.action == "connect":
            if not args.host:
                console.log("[red]error[/red]: no host address provided")
                return

            with Progress(
                f"connecting to [blue]{args.host}[/blue]:[cyan]{args.port}[/cyan]",
                BarColumn(bar_width=None),
            ) as progress:
                task_id = progress.add_task("connecting", total=1, start=False)
                # Connect to the remote host
                client = socket.create_connection((args.host, args.port))

                progress.update(task_id, visible=False)
                progress.log(
                    f"connection to "
                    f"[blue]{args.host}[/blue]:[cyan]{args.port}[/cyan] [green]established[/green]"
                )

                pwncat.victim.connect(client)
        elif args.action == "ssh":

            if not args.port:
                args.port = 22

            if not args.user:
                self.parser.error("you must specify a user")

            if not (args.password or args.identity):
                self.parser.error("either a password or identity file is required")

            try:
                # Connect to the remote host's ssh server
                sock = socket.create_connection((args.host, args.port))
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
                    t.auth_publickey(args.user, key)
                except paramiko.ssh_exception.AuthenticationException as exc:
                    console.log(f"[red]error[/red]: authentication failed: {exc}")
            else:
                try:
                    t.auth_password(args.user, args.password)
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
        elif args.action == "reconnect":
            if not args.host:
                self.parser.error("host address or hash is required for reconnection")

            try:
                addr = ipaddress.ip_address(args.host)
                host = (
                    pwncat.victim.session.query(pwncat.db.Host)
                    .filter_by(ip=str(addr))
                    .first()
                )
                if host is None:
                    console.log(f"[red]error[/red]: {args.host}: not found in database")
                    return
                host_hash = host.hash
            except ValueError:
                host_hash = args.host

            # Reconnect to the given host
            try:
                pwncat.victim.reconnect(host_hash, args.method, args.user)
            except PersistenceError as exc:
                console.log(f"[red]error[/red]: {args.host}: {exc}")
                return
        elif args.action == "list":
            if pwncat.victim.session is not None:
                for host in pwncat.victim.session.query(pwncat.db.Host):
                    if len(host.persistence) == 0:
                        continue
                    console.print(
                        f"[magenta]{host.ip}[/magenta] - [red]{host.distro}[/red] - [yellow]{host.hash}[/yellow]"
                    )
                    for p in host.persistence:
                        console.print(
                            f"  - [blue]{p.method}[/blue] as [green]{p.user if p.user else 'system'}[/green]"
                        )
        else:
            console.log(f"[red]error[/red]: {args.action}: invalid action")
