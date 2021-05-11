#!/usr/bin/env python3
import socket
from typing import Optional

from rich.progress import Progress, BarColumn

from pwncat.channel import Channel, ChannelError
from pwncat.channel.socket import Socket


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
            raise ChannelError(self, f"no port specified")

        super().__init__(client=None, host=host, port=port, **kwargs)

        self.address = (host, port)
        self.server = socket.create_server((host, port), reuse_port=True)

    def connect(self):

        with Progress(
            f"bound to [blue]{self.host}[/blue]:[cyan]{self.port}[/cyan]",
            BarColumn(bar_width=None),
            transient=True,
        ) as progress:
            task_id = progress.add_task("listening", total=1, start=False)

            try:
                # Wait for a connection
                (client, address) = self.server.accept()
                self._socket_connected(client)
            except KeyboardInterrupt:
                raise ChannelError(self, "listener aborted")
            finally:
                self.server.close()

            progress.update(task_id, visible=False)
            progress.log(
                f"[green]received[/green] connection from [blue]{address[0]}[/blue]:[cyan]{address[1]}[/cyan]"
            )
