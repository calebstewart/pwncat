#!/usr/bin/env python3
import time
from typing import Optional, Type

CHANNEL_TYPES = {}


class ChannelError(Exception):
    """ Raised when a channel fails to connect """


class ChannelTimeout(Exception):
    """ Raised when a read times out.

    :param data: the data read before the timeout occurred
    :type data: bytes
    """

    def __init__(self, data: bytes):
        super().__init__("channel recieve timed out")
        self.data: bytes = data


class Channel:
    """
    Abstract interation with a remote victim. This class acts similarly to a
    socket object. In the common cases, it simply wraps a socket object.
    """

    def __init__(self, host: str, port: int, user: str, password: str, **kwargs):
        self.host: str = host
        self.port: int = port
        self.user: str = user
        self.password: str = password

        self.peek_buffer: bytes = b""

    def send(self, data: bytes):
        """ Send data to the remote shell. This is a blocking call
        that only returns after all data is sent. """

    def sendline(self, data: bytes, end: bytes = b"\n"):
        """ Send data followed by an ending character. If no ending
        character is specified, a new line is used. """

        return self.send(data + end)

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

    def recvuntil(self, needle: bytes, timeout: Optional[float] = None) -> bytes:
        """ Receive data until the specified string of bytes is bytes
        is found. The needle is not stripped from the data.

        :param needle: the bytes to wait for
        :type needle: bytes
        :param timeout: a timeout in seconds (default: 30s)
        :type timeout: Optional[float]
        :return: the bytes that were read
        :rtype: bytes
        """

        if timeout is None:
            timeout = 30

        data = b""
        time_end = time.time() + timeout

        # We read one byte at a time so we don't overshoot the goal
        while not data.endswith(needle):

            # Check if we have timed out
            if time.time() >= time_end:
                raise ChannelTimeout(data)

            next_byte = self.recv(1)

            if next_byte is not None:
                data += next_byte

        return data

    def recvline(self, timeout: Optional[float] = None) -> bytes:
        """ Recieve data until a newline is received. The newline
        is not stripped. """

        return self.recvuntil(b"\n", timeout=timeout)

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

        # Grab any already buffered data
        if self.peek_buffer:
            data = self.peek_buffer
        else:
            data = b""

        # Check for more data within our count
        if len(data) < count:
            self.peek_buffer = b""
            data += self.recv(count - len(data))
            self.peek_buffer = data

        return data


def register(name: str, channel_class):
    """
    Register a new channel class with ``pwncat``.

    :param name: the name which this channel will be referenced by.
    :type name: str
    :param channel_class: A class object implementing the channel
      interface.
    """

    CHANNEL_TYPES[name] = channel_class


def find(name: str) -> Type[Channel]:
    """
    Retrieve the channel class for the specified name.

    :param name: the name of the channel you'd like
    :type name: str
    :return: the channel class
    :rtype: Channel Class Object
    """

    return CHANNEL_TYPES[name]


# Import default channel types and register them
from pwncat.channel.bind import Bind
from pwncat.channel.connect import Connect
from pwncat.channel.ssh import Ssh

register("bind", Bind)
register("connect", Connect)
register("ssh", Ssh)
