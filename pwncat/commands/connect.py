#!/usr/bin/env python3
from colorama import Fore
import ipaddress
import socket

import paramiko
from prompt_toolkit import prompt

import pwncat
from pwncat import util
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    parameter,
    StoreForAction,
    StoreConstOnce,
)
from pwncat.persist import PersistenceError


class Command(CommandDefinition):
    """ Connect to a remote host via SSH, bind/reverse shells or previous
    persistence methods installed during past sessions. """

    PROG = "connect"
    ARGS = {
        "--exit": parameter(
            Complete.NONE, action="store_true", help="Exit if not connection is made"
        ),
        "--config,-C": parameter(
            Complete.NONE,
            help="Path to a configuration script to execute prior to connecting",
        ),
        "--listen,-l": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="listen",
            nargs=0,
            help="Listen for an incoming reverse shell",
        ),
        "--connect,-c": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="connect",
            nargs=0,
            help="Connect to a remote bind shell",
        ),
        "--ssh,-s": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="ssh",
            nargs=0,
            help="Connect to a remote ssh server",
        ),
        "--reconnect,-r": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="reconnect",
            nargs=0,
            help="Reconnect to the given host via a persistence method",
        ),
        "--list": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            dest="action",
            const="list",
            nargs=0,
            help="List remote hosts with persistence methods installed",
        ),
        "--host,-H": parameter(
            Complete.NONE,
            help="Address to listen on or remote host to connect to. For reconnections, this can be a host hash",
        ),
        "--port,-p": parameter(
            Complete.NONE,
            type=int,
            help="The port to listen on or connect to",
            action=StoreForAction(["connect", "listen"]),
        ),
        "--method,-m": parameter(
            Complete.NONE,
            help="The method to user for reconnection",
            action=StoreForAction(["reconnect"]),
        ),
        "--user,-u": parameter(
            Complete.NONE,
            help="The user to reconnect as; if this is a system method, this parameter is ignored.",
            action=StoreForAction(["reconnect", "ssh"]),
        ),
        "--password,-P": parameter(
            Complete.NONE,
            help="The password for the specified user for SSH connections",
            action=StoreForAction(["ssh"]),
        ),
        "--identity,-i": parameter(
            Complete.NONE,
            help="The private key for authentication for SSH connections",
            action=StoreForAction(["ssh"]),
        ),
    }
    DEFAULTS = {"action": "connect"}
    LOCAL = True

    def run(self, args):

        if pwncat.victim.client is not None:
            util.error("connect can only be called prior to an active connection!")
            return

        if args.config:
            try:
                # Load the configuration
                with open(args.config, "r") as filp:
                    pwncat.victim.command_parser.eval(filp.read(), args.config)
            except OSError as exc:
                self.parser.error(str(exc))

        try:
            if args.action == "listen":
                if not args.host:
                    args.host = "0.0.0.0"

                util.progress(f"binding to {args.host}:{args.port}")

                # Create the socket server
                server = socket.create_server((args.host, args.port), reuse_port=True)

                try:
                    # Wait for a connection
                    (client, address) = server.accept()
                except KeyboardInterrupt:
                    util.warn(f"aborting listener...")
                    return

                util.success(f"received connection from {address[0]}:{address[1]}")
                pwncat.victim.connect(client)
            elif args.action == "connect":
                if not args.host:
                    self.parser.error(
                        "host address is required for outbound connections"
                    )

                util.progress(f"connecting to {args.host}:{args.port}")

                # Connect to the remote host
                client = socket.create_connection((args.host, args.port))

                util.success(f"connection to {args.host}:{args.port} established")
                pwncat.victim.connect(client)
            elif args.action == "ssh":

                if not args.port:
                    args.port = 22

                if not args.user:
                    self.parser.error("you must specify a user")

                if not args.password and not args.identity:
                    self.parser.error("either a password or identity file is required")

                try:
                    # Connect to the remote host's ssh server
                    sock = socket.create_connection((args.host, args.port))
                except Exception as exc:
                    util.error(str(exc))
                    return

                # Create a paramiko SSH transport layer around the socket
                t = paramiko.Transport(sock)
                try:
                    t.start_client()
                except paramiko.SSHException:
                    sock.close()
                    util.error("ssh negotiation failed")
                    return

                if args.identity:
                    try:
                        # Load the private key for the user
                        key = paramiko.RSAKey.from_private_key_file(
                            pwncat.victim.config["privkey"]
                        )
                    except:
                        password = prompt(
                            "RSA Private Key Passphrase: ", is_password=True
                        )
                        key = paramiko.RSAKey.from_private_key_file(
                            pwncat.victim.config["privkey"], password
                        )

                    # Attempt authentication
                    try:
                        t.auth_publickey(args.user, key)
                    except paramiko.ssh_exception.AuthenticationException:
                        pass
                else:
                    try:
                        t.auth_password(args.user, args.password)
                    except paramiko.ssh_exception.AuthenticationException:
                        pass

                if not t.is_authenticated():
                    t.close()
                    sock.close()
                    util.error("authentication failed")
                    return

                # Open an interactive session
                chan = t.open_session()
                chan.get_pty()
                chan.invoke_shell()

                # Initialize the session!
                pwncat.victim.connect(chan)
            elif args.action == "reconnect":
                if not args.host:
                    self.parser.error(
                        "host address or hash is required for reconnection"
                    )

                try:
                    addr = ipaddress.ip_address(args.host)
                    util.progress(f"enumerating persistence methods for {addr}")
                    host = (
                        pwncat.victim.session.query(pwncat.db.Host)
                        .filter_by(ip=str(addr))
                        .first()
                    )
                    if host is None:
                        util.error(f"{args.host}: not found in database")
                        return
                    host_hash = host.hash
                except ValueError:
                    host_hash = args.host

                # Reconnect to the given host
                try:
                    pwncat.victim.reconnect(host_hash, args.method, args.user)
                except PersistenceError as exc:
                    util.error(f"{host_hash}: connection failed: {exc}")
                    return
            elif args.action == "list":
                if pwncat.victim.session is not None:
                    for host in pwncat.victim.session.query(pwncat.db.Host):
                        if len(host.persistence) == 0:
                            continue
                        print(
                            f"{Fore.MAGENTA}{host.ip}{Fore.RESET} - {Fore.RED}{host.distro}{Fore.RESET} - {Fore.YELLOW}{host.hash}{Fore.RESET}"
                        )
                        for p in host.persistence:
                            print(
                                f"  - {Fore.BLUE}{p.method}{Fore.RESET} as {Fore.GREEN}{p.user if p.user else 'system'}{Fore.RESET}"
                            )
            else:
                util.error(f"{args.action}: invalid action")
        finally:
            if pwncat.victim.client is None and args.exit:
                raise SystemExit
