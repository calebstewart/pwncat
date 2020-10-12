#!/usr/bin/env python3
import socket
from typing import Optional

from rich.progress import BarColumn, Progress

from pwncat.channel import Channel, ChannelError


class Connect(Channel):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel will listen for incoming
    connections on the specified port, and assume the resulting
    connection is a shell from the victim.
    """

    def __init__(self, host: str, port: int, user: str, password: str, **kwargs):
        super().__init__(host, port, user, password)

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

        self.client = client
        self.address = (host, port)

    def send(self, data: bytes):
        """ Send data to the remote shell. This is a blocking call
        that only returns after all data is sent. """

        self.client.sendall(data)

        return len(data)

    def recv(self, count: Optional[int] = None) -> bytes:
        """ Receive data from the remote shell

        If your channel class does not implement ``peak``, a default
        implementation is provided. In this case, you can use the
        ``_pop_peek`` to get available peek buffer data prior to
        reading data like a normal ``recv``.

        :param count: maximum number of bytes to receive (default: unlimited)
        :type count: int
        :return: the data that was received
        :rtype: bytes
        """

        return self.client.recv(count)

    def recvuntil(self, needle: bytes) -> bytes:
        """ Receive data until the specified string of bytes is bytes
        is found. The needle is not stripped from the data. """

        data = b""

        # We read one byte at a time so we don't overshoot the goal
        while not data.endswith(needle):
            next_byte = self.recv(1)

            if next_byte is not None:
                data += next_byte

        return data

    def peek(self, count: Optional[int] = None):
        """ Receive data from the remote shell and leave
        the data in the recv buffer.

        There is a default implementation for this method which will
        utilize ``recv`` to get data, and buffer it. If the default
        ``peek`` implementation is used, ``recv`` should read from
        ``self.peek_buffer`` prior to calling the underlying ``recv``.

        :param count: maximum number of bytes to receive (default: unlimited)
        :type count: int
        :return: data that was received
        :rtype: bytes
        """

        return self.client.recv(count, socket.MSG_PEEK)
