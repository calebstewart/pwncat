#!/usr/bin/env python3
import socket
import errno
import fcntl
import os
from typing import Optional

from rich.progress import BarColumn, Progress

from pwncat.channel import Channel, ChannelError, ChannelClosed


class Connect(Channel):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel will listen for incoming
    connections on the specified port, and assume the resulting
    connection is a shell from the victim.
    """

    def __init__(self, host: str, port: int, **kwargs):
        super().__init__(host, port, **kwargs)

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

        # Ensure we are non-blocking
        self.client.setblocking(False)
        fcntl.fcntl(self.client, fcntl.F_SETFL, os.O_NONBLOCK)

    def send(self, data: bytes):
        """ Send data to the remote shell. This is a blocking call
        that only returns after all data is sent. """

        try:
            written = 0
            while written < len(data):
                try:
                    written += self.client.send(data[written:])
                except BlockingIOError:
                    pass
        except BrokenPipeError as exc:
            raise ChannelClosed(self) from exc

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

        if self.peek_buffer:
            data = self.peek_buffer[:count]
            self.peek_buffer = self.peek_buffer[len(data) :]
            count -= len(data)
        else:
            data = b""

        try:
            return data + self.client.recv(count)
        except socket.error as exc:
            if exc.args[0] == errno.EAGAIN or exc.args[0] == errno.EWOULDBLOCK:
                return data

            raise ChannelClosed(self) from exc

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

        if self.peek_buffer:
            data = self.peek_buffer[:count]
            count -= len(data)
        else:
            data = b""

        try:
            return data + self.client.recv(count)
        except socket.error as exc:
            if exc.args[0] == errno.EAGAIN or exc.args[0] == errno.EWOULDBLOCK:
                return data

            raise ChannelClosed(self) from exc

    def fileno(self):
        return self.client.fileno()
