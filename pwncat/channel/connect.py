#!/usr/bin/env python3
import socket
import errno
import fcntl
import os
from typing import Optional

from rich.progress import BarColumn, Progress

from pwncat.channel.socket import Socket
from pwncat.channel import Channel, ChannelError, ChannelClosed


class Connect(Socket):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel will listen for incoming
    connections on the specified port, and assume the resulting
    connection is a shell from the victim.
    """

    def __init__(self, host: str, port: int, **kwargs):
        if not host:
            raise ChannelError("no host address provided")

        if port is None:
            raise ChannelError("no port provided")

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

        super().__init__(client=client, host=host, port=port, **kwargs)
