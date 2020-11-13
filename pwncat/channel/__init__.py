#!/usr/bin/env python3
import time
from typing import Optional, Type, Union
from io import RawIOBase, BufferedReader, BufferedWriter, DEFAULT_BUFFER_SIZE

CHANNEL_TYPES = {}


class ChannelError(Exception):
    """ Raised when a channel fails to connect """

    def __init__(self, ch, msg="generic channel failure"):
        super().__init__(msg)
        self.channel = ch


class ChannelClosed(ChannelError):
    """ A channel was closed unexpectedly during communication """

    def __init__(self, ch):
        super().__init__(ch, "channel unexpectedly closed")

    def cleanup(self, manager: "pwncat.manager.Manager"):
        """ Cleanup this channel from the manager """

        # If we don't have a session, there's nothing to do
        session = manager.find_session_by_channel(self.channel)
        if session is None:
            return

        # Session takes care of removing itself from the manager
        # and unsetting `manager.target` if needed.
        session.died()


class ChannelTimeout(ChannelError):
    """ Raised when a read times out.

    :param data: the data read before the timeout occurred
    :type data: bytes
    """

    def __init__(self, ch, data: bytes):
        super().__init__(ch, "channel recieve timed out")
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
        self.found_sof = False
        self.on_close = on_close
        self.eof = False

        if not text:
            self.mode += "b"

        # Ignored if text == False, but saved none the less
        self.encoding = encoding

        if self.sof_marker is not None and "r" in self.mode:
            self.channel.recvuntil(self.sof_marker)
            self.found_sof = True

    def readable(self) -> bool:
        return "r" in self.mode

    def writable(self) -> bool:
        return "w" in self.mode

    def close(self):

        if self.eof:
            return

        self.eof = True

        if self.on_close is not None:
            self.on_close(self)

    def readall(self):
        """ Read all data until EOF """

        data = b""

        while not self.eof:
            new_data = self.read(4096)
            if new_data is None:
                continue
            data += new_data

        return data

    def readinto(self, b: Union[memoryview, bytearray]):

        # If we already hit EOF, don't read anymore
        if self.eof:
            return 0

        # Check the type of the argument, and grab the relevant part
        obj = b.obj if isinstance(b, memoryview) else b
        n = 0

        while n == 0:
            try:
                n = self.channel.recvinto(b)
            except NotImplementedError:
                # recvinto was not implemented, fallback recv
                data = self.channel.recv(len(b))
                b[: len(data)] = data
                n = len(data)

        obj = bytes(b[:n])

        # Check for explicit EOF in this block
        if self.eof_marker in obj:
            # Remove the marker from the output data
            # and unreceive any data not bound for us
            new_n = obj.find(self.eof_marker)
            if (n - new_n) > len(self.eof_marker):
                # We read more than the EOF marker, replace it in the buffer
                self.channel.unrecv(obj[new_n + len(self.eof_marker) :])

            # Ensure further reads don't work
            self.close()

            return new_n

        # Check for EOF split across blocks
        for i in range(1, len(self.eof_marker)):
            # See if a piece of the delimeter is at the end of this block
            piece = self.eof_marker[:i]

            if obj[-i:] == piece:
                # Peek enough bytes from the buffer to see if the rest of the
                # EOF marker is there.
                rest = self.channel.peek(len(self.eof_marker) - len(piece))

                # Are the next bytes we would read the last of the EOF marker?
                if (piece + rest) == self.eof_marker:
                    # Receive the rest of the marker
                    self.channel.recv(len(rest))
                    # Adjust the number of bytes read
                    n -= len(piece)
                    # Mark the stream as closed
                    self.close()
                    return n

        if n == 0:
            return None

        return n

    def write(self, data: bytes):

        if self.eof:
            return 0

        written = 0
        while written < len(data):
            written += self.channel.send(data)

        return written


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

    @property
    def connected(self):
        """ Check if this channel is connected. This should return
        false prior to an established connection, and may return
        true prior to the ``connect`` method being called for some
        channel types. """

    def connect(self):
        """ Utilize the parameters provided at initialization to
        connect to the remote host. This is mainly used for channels
        which listen for a connection. In that case, `__init__` creates
        the listener while connect actually establishes a connection.
        For direct connection-type channels, all logic can be implemented
        in the constructor.

        This method is called when creating a platform around this channel
        to instantiate the session.
        """

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
        return b""

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

    def unrecv(self, data: bytes):
        """
        Place the given bytes on a buffer to be returned next by recv.
        If you do not implement a custom ``peek``, you can use the builtin
        implementation. If the ``peek_buffer`` is not used, then you must
        implement this logic yourself.
        """

        # This makes the next recv return this data first
        self.peek_buffer = data + self.peek_buffer

    def recvinto(self, *args, **kwargs):
        """
        Base method simply raises a NotImplementedError
        """
        raise NotImplementedError

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
        bufsize: int = -1,
        sof: Optional[bytes] = None,
        eof: Optional[bytes] = None,
    ):
        """
        Create a file-like object which acts on this channel. If the mode is
        "r", and ``sof`` and ``eof`` are specified, the file will return data
        following a line containing only ``sof`` and up to a line containing only
        ``eof``. In "w" mode, the file has no bounds and will never hit ``eof``.

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

        raw_io = ChannelFile(self, mode, sof, eof)

        if bufsize < 0 or bufsize is None:
            bufsize = DEFAULT_BUFFER_SIZE

        if mode == "r":
            return BufferedReader(raw_io, buffer_size=bufsize)
        else:
            return BufferedWriter(raw_io, buffer_size=bufsize)

    def close(self):
        """ Close this channel. This method should do nothing if
        the ``connected`` property returns False. """

    def __str__(self):
        """ Get a representation of this channel """

        return f"[cyan]{self.address[0]}[/cyan]:[blue]{self.address[1]}[/blue]"


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
        protocols = []  # ["reconnect"]

        if "user" in kwargs and kwargs["user"] is not None:
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
# register("reconnect", Reconnect)
