#!/usr/bin/env python3
from io import TextIOWrapper
import logging
import selectors
import shlex
import sys
import warnings
import os
import argparse
from pathlib import Path

from sqlalchemy import exc as sa_exc
from sqlalchemy.exc import InvalidRequestError
from paramiko.buffered_pipe import BufferedPipe

import pwncat.manager
from pwncat.util import console
from pwncat.commands import connect


def main():

    # Ignore SQL Alchemy warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", category=sa_exc.SAWarning)

        # Default log-level is "INFO"
        logging.getLogger().setLevel(logging.INFO)

        parser = argparse.ArgumentParser()
        parser.add_argument(
            "--config",
            "-c",
            type=argparse.FileType("r"),
            default="./pwncatrc",
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
            "--platform", "-m", help="Name of the platform to use (default: linux)"
        )
        parser.add_argument(
            "--port",
            "-p",
            help="Alternative way to specify port to support netcat-style syntax",
        )
        parser.add_argument(
            "--list",
            action="store_true",
            help="List known hosts and any installed persistence",
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
        args = parser.parse_args()

        # Create the session manager
        manager = pwncat.manager.Manager(args.config)

        if args.list:

            with manager.new_db_session() as db:
                hosts = {
                    host.hash: (host, []) for host in db.query(pwncat.db.Host).all()
                }

            for host_hash, (host, modules) in hosts.items():
                console.print(
                    f"[magenta]{host.ip}[/magenta] - "
                    f"[red]{host.distro}[/red] - "
                    f"[yellow]{host_hash}[/yellow]"
                )
                for module in modules:
                    console.print(f"  - {str(module)}")

            return

        if (
            args.connection_string is not None
            or args.pos_port is not None
            or args.port is not None
            or args.platform is not None
            or args.listen is not None
            or args.identity is not None
        ):
            protocol = None
            user = None
            password = None
            host = None
            port = None
            try_reconnect = False

            if args.connection_string:
                m = connect.Command.CONNECTION_PATTERN.match(args.connection_string)
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
                sum(
                    [port is not None, args.port is not None, args.pos_port is not None]
                )
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
                console.log(
                    f"[red]error[/red]: --identity is only valid for ssh protocols"
                )
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

        manager.interactive()


if __name__ == "__main__":

    main()

    sys.exit(0)
