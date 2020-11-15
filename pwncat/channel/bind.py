#!/usr/bin/env python3
import socket
from typing import Optional

from rich.progress import BarColumn, Progress

from pwncat.channel.socket import Socket
from pwncat.channel import Channel, ChannelError


class Bind(Socket):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel will listen for incoming
    connections on the specified port, and assume the resulting
    connection is a shell from the victim.
    """

    def __init__(self, port: int, host: str = None, **kwargs):

        if not host or host == "":
            host = "0.0.0.0"

        if port is None:
            raise ChannelError(f"no port specified")

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
                raise ChannelError("listener aborted")

            progress.update(task_id, visible=False)
            progress.log(
                f"[green]received[/green] connection from [blue]{address[0]}[/blue]:[cyan]{address[1]}[/cyan]"
            )

        super().__init__(client=client, host=host, port=port, **kwargs)
