#!/usr/bin/env python3
import os
import errno
import fcntl
import socket
from typing import Optional

from rich.progress import Progress, BarColumn

from pwncat.channel import Channel, ChannelError, ChannelClosed


def connect_required(method):
    def _wrapper(self, *args, **kwargs):
        if not self.connected:
            raise ChannelError(self, "channel not connected")
        return method(self, *args, **kwargs)

    return _wrapper


class Socket(Channel):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel takes an existing
    socket as an argument, and allows pwncat to reuse
    an existing connection.
    """

    def __init__(self, client: socket.socket = None, **kwargs):

        if client is not None:
            # Report host and port number to base channel
            host, port = client.getpeername()

            if "host" not in kwargs:
                kwargs["host"] = host
            if "port" not in kwargs:
                kwargs["port"] = port

        super().__init__(**kwargs)

        self._connected = False

        if client is not None:
            self._socket_connected(client)

    @property
    def connected(self):
        return self._connected

    def _socket_connected(self, client: socket.socket):
        """Notify the channel that the socket is now connected.
        This is mainly used for binding sockets where the initial
        socket creation is only the server, and the client is
        connected during the ``connect`` method."""

        self._connected = True
        self.client = client
        self.address = client.getpeername()

        self.client.setblocking(False)
        fcntl.fcntl(self.client, fcntl.F_SETFL, os.O_NONBLOCK)

    @connect_required
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

    @connect_required
    def recv(self, count: Optional[int] = None) -> bytes:
        """Basic socket recv wrapper. This also uses the default
        ``peek`` implementation. This could be optimized to use
        the socket native ``peek`` method.

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

    @connect_required
    def close(self):
        self._connected = False
        self.client.close()

    @connect_required
    def fileno(self):
        return self.client.fileno()
