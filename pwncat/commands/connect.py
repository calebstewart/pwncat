#!/usr/bin/env python3
import ipaddress
import socket

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
            action=StoreForAction(["reconnect"]),
        ),
    }
    DEFAULTS = {"action": "list"}
    LOCAL = True

    def run(self, args):

        if pwncat.victim.client is not None:
            util.error("connect can only be called prior to an active connection!")
            return

        if args.action == "listen":
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
            util.progress(f"connecting to {args.host}:{args.port}")

            # Connect to the remote host
            client = socket.create_connection((args.host, args.port))

            util.success(f"connection to {args.host}:{args.port} established")
            pwncat.victim.connect(client)
        elif args.action == "ssh":
            raise NotImplementedError
        elif args.action == "reconnect":
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
                pwncat.victim.reconnect(host_hash)
            except PersistenceError as exc:
                util.error(f"{host_hash}: connection failed: {exc}")
                return
        else:
            util.error(f"{args.action}: invalid action")
