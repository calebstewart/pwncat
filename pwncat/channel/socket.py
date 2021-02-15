#!/usr/bin/env python3
import socket
import errno
import fcntl
import os
from typing import Optional

from rich.progress import BarColumn, Progress

from pwncat.channel import Channel, ChannelError, ChannelClosed


class Socket(Channel):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel takes an existing
    socket as an argument, and allows pwncat to reuse
    an existing connection.
    """

    def __init__(self, client: socket.socket, **kwargs):

        # Report host and port number to base channel
        host, port = client.getpeername()

        if "host" not in kwargs:
            kwargs["host"] = host
        if "port" not in kwargs:
            kwargs["port"] = port

        super().__init__(**kwargs)

        self._connected = True
        self.client = client
        self.address = (host, port)

        # Ensure we are non-blocking
        self.client.setblocking(False)
        fcntl.fcntl(self.client, fcntl.F_SETFL, os.O_NONBLOCK)

    @property
    def connected(self):
        return self._connected

    def send(self, data: bytes):
        """Send data to the remote shell. This is a blocking call
        that only returns after all data is sent."""

        try:
            written = 0
            while written < len(data):
                try:
                    written += self.client.send(data[written:])
                except BlockingIOError:
                    pass
        except BrokenPipeError as exc:
            self._connected = False
            raise ChannelClosed(self) from exc

        return len(data)

    def recv(self, count: Optional[int] = None) -> bytes:
        """Receive data from the remote shell

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

            self._connected = False
            raise ChannelClosed(self) from exc

    def peek(self, count: Optional[int] = None):
        """Receive data from the remote shell and leave
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

            self._connected = False
            raise ChannelClosed(self) from exc

    def close(self):
        self._connected = False
        self.client.close()

    def fileno(self):
        return self.client.fileno()
