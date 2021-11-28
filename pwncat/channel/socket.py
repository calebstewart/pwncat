"""
This is the base class for all socket-based channels. Both bind and
connect protocols utilize this base class. You can also programmatically
utilize this class to instantiate a session via an established socket.

.. code-block:: python

    # Manually connect to a service and trigger a shell on the same socket
    sock = socket.create_connection(("192.168.1.1", 1337))

    # Create a manager
    with pwncat.manager.Manager() as manager:
        # Create a pwncat session around our socket
        session = manager.create_connection(platform="linux", protocol="socket", client=sock)
        manager.interactive()
"""
import os
import ssl
import errno
import fcntl
import socket
import functools
from typing import Optional

from pwncat.channel import Channel, ChannelError, ChannelClosed


def connect_required(method):
    """Channel method decorator which verifies that the channel
    is connected prior to executing the wrapped method. If the
    channel is not connected, a :class:`ChannelError` is raised."""

    @functools.wraps(method)
    def _wrapper(self, *args, **kwargs):
        if not self.connected:
            raise ChannelClosed(self)
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

        if isinstance(client, str):
            raise ChannelError(self, f"expected socket object not {repr(type(client))}")

        if client is not None:
            # Report host and port number to base channel
            host, port, *_ = client.getpeername()

            # Localhost is sometimes a IPv4 and sometimes IPv6 socket, just normalize the name
            if host == "::1" or host == "127.0.0.1":
                host = "localhost"

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

        # Localhost is sometimes a IPv4 and sometimes IPv6 socket, just normalize the name
        if self.address[0] == "::1" or self.address[0] == "127.0.0.1":
            self.address = ("localhost", *self.address[1:])

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
                except (BlockingIOError, ssl.SSLWantWriteError, ssl.SSLWantReadError):
                    pass
        except BrokenPipeError as exc:
            self._connected = False
            raise ChannelClosed(self) from exc
        except (ssl.SSLEOFError, ssl.SSLSyscallError, ssl.SSLZeroReturnError) as exc:
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

        if count == 0:
            return data

        try:
            new_data = self.client.recv(count)
            if new_data == b"":
                self._connected = False
                raise ChannelClosed(self)
            return data + new_data
        except BlockingIOError:
            return data
        except ssl.SSLWantReadError:
            return data
        except (ssl.SSLEOFError, ssl.SSLSyscallError, ssl.SSLZeroReturnError) as exc:
            self._connected = False
            raise ChannelClosed(self) from exc
        except socket.error as exc:
            if exc.args[0] == errno.EAGAIN or exc.args[0] == errno.EWOULDBLOCK:
                return data

            self._connected = False
            raise ChannelClosed(self) from exc

    def close(self):
        if not self._connected:
            return

        self._connected = False
        self.client.close()

    @connect_required
    def fileno(self):
        return self.client.fileno()
