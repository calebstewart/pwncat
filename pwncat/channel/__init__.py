#!/usr/bin/env python3
import time
from typing import Optional, Type
from io import RawIOBase

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


class ChannelFile(RawIOBase):
    """
    Wrap a channel in a file-like object. Mainly used for process IO by
    the platform wrappers. It enables platforms to quickly create a file-like
    object which is bounded by a delimeter and can be returned to the user
    safely.
    """

    def __init__(
        self,
        channel: "Channel",
        mode: str,
        sof: Optional[bytes] = None,
        eof: Optional[bytes] = None,
        text: Optional[bool] = False,
        encoding: str = "utf-8",
        on_close=None,
    ):
        self.channel = channel
        self.mode = mode
        self.sof_marker = sof
        self.eof_marker = eof
        self.on_close = on_close
        self.eof = False

        if not text:
            self.mode += "b"

        # Ignored if text == False, but saved none the less
        self.encoding = encoding

    def readable(self) -> bool:
        return "r" in self.mode

    def writable(self) -> bool:
        return "w" in self.mode

    def on_eof(self):
        """ Executed whenever EOF is found """

        if self.eof:
            return

        self.eof = True

        if self.on_close is not None:
            self.on_close(self)

    def close(self):

        if self.eof:
            return

        self.on_eof()


class Channel:
    """
    Abstract interation with a remote victim. This class acts similarly to a
    socket object. In the common cases, it simply wraps a socket object.
    """

    def __init__(
        self,
        host: str,
        port: int = None,
        user: str = None,
        password: str = None,
        **kwargs,
    ):
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

    def drain(self, some: bool = False):
        """ Drain any incoming data from the remote host. In general
        this is implemented by reading data until a timeout occurs,
        however implementations may differ by the type of channel.
        The received data is discarded and never buffered.

        If ``some`` is True, then this method should ignore timeouts
        until at least one byte of data is received. This is used when
        we know that some data should be sent, and we want to drain
        it from the buffer before continuing.

        :param some: whether to wait for at least one byte of data
        :type some: bool
        :return: a boolean indicating whether the file is at EOF
        :rtype: bool
        """

    def makefile(
        self,
        mode: str,
        sof: Optional[bytes] = None,
        eof: Optional[bytes] = None,
        text: bool = False,
        encoding: Optional[str] = "utf-8",
    ):
        """
        Create a file-like object which acts on this channel. If the mode is
        "r", and ``sof`` and ``eof`` are specified, the file will return data
        following a line containing only ``sof`` and up to a line containing only
        ``eof``. In "w" mode, the file has no bounds and will never hit ``eof``.

        If ``text`` is true, a text-mode file object will be returned which decodes
        the output with the specified encoding. The default encoding is utf-8.

        :param mode: a mode string similar to open
        :type mode: str
        :param sof: a string of bytes which indicate the start of file
        :type sof: bytes
        :param eof: a string of bytes which indicate the end of file
        :type eof: bytes
        :param text: whether to produce a text-mode file-like object
        :type text: bool
        :param encoding: the encoding used when creating a text-mode file
        :type encoding: str
        :return: A file-like object suitable for the specified mode
        :rtype: Union[BinaryIO, TextIO]
        :raises:
          ValueError: both "r" and "w" were specified or invalid characters were found in mode
        """

        if mode != "r" and mode != "w":
            raise ValueError(f"{mode}: invalid mode")


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


def create(protocol: Optional[str] = None, **kwargs):
    """
    Create a new channel with the class provided by a registered channel
    protocol. Some assumptions are made if the protocol is not specified.
    For example, if no username or password are specified, then either
    bind or connect protocols are assumed. If a username is specified,
    the ssh protocol is assumed. In any case, with no protocol, a reconnect
    is attempted first.

    :param protocol: the name of the register channel protocol (e.g. ssh, bind,
      connect)
    :type protocol: Optional[str]
    :return: A newly connected channel
    :rtype: Channel
    :raises:
      ChannelError: if the victim cannot be reached via the specified
        protocol
    """

    if protocol is None:
        protocols = ["reconnect"]

        if "user" in kwargs:
            protocols.append("ssh")
        else:
            if "host" not in kwargs or kwargs["host"] == "0.0.0.0":
                protocols.append("bind")
            else:
                protocols.append("connect")
    else:
        protocols = [protocol]

    for prot in protocols:
        try:
            channel = find(prot)(**kwargs)
            return channel
        except ChannelError:
            if len(protocols) == 1 or prot != "reconnect":
                raise


# Import default channel types and register them
from pwncat.channel.bind import Bind
from pwncat.channel.connect import Connect
from pwncat.channel.ssh import Ssh
from pwncat.channel.reconnect import Reconnect

register("bind", Bind)
register("connect", Connect)
register("ssh", Ssh)
register("reconnect", Reconnect)
