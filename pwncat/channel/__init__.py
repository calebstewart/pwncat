"""
Channels represent the basic communication object within pwncat. Each channel
abstracts a communication method with a target. By default, pwncat implements
a few standard channels: socket bind/connect and ssh.

A channel largely mimicks a standard socket, however exact compatibility with
sockets was not the goal. Instead, it provides a low-level communication channel
between the target and the attacker. Channels make no assumption about protocol
of the C2 connection. This is the platform's job.

As a user, you will never directly create a channel. Instead, you will call
:func:`pwncat.manager.Manager.create_session`. This method will in turn
locate an appropriate channel based on your arguments, and pass all arguments
to the constructor for the appropriate channel type.
"""
import time
from io import DEFAULT_BUFFER_SIZE, RawIOBase, BufferedReader, BufferedWriter
from abc import ABC, abstractmethod
from typing import Type, Union, Optional

import pwncat

CHANNEL_TYPES = {}


class ChannelError(Exception):
    """Generic failure of a channel operation.

    :param ch: the channel which caused the exception
    :type ch: Channel
    :param msg: a message describing the failure
    :type msg: str
    """

    def __init__(self, ch, msg="generic channel failure"):
        super().__init__(msg)
        self.channel = ch


class ChannelClosed(ChannelError):
    """A channel was closed unexpectedly during communication. This
    exception provides a :func:`cleanup` method which will cleanup the
    channel within the manager to ensure no further errors occur.
    This method is normally called by the manager itself upon catching
    the exception, but you should call this method if you intercept
    and do not re-throw the exception.

    :param ch: the channel which caused the exception
    :type ch: Channel
    """

    def __init__(self, ch):
        super().__init__(ch, "channel unexpectedly closed")

    def cleanup(self, manager: "pwncat.manager.Manager"):
        """Cleanup this channel from the manager"""

        # If we don't have a session, there's nothing to do
        session = manager.find_session_by_channel(self.channel)
        if session is None:
            return

        # Session takes care of removing itself from the manager
        # and unsetting `manager.target` if needed.
        session.died()


class ChannelTimeout(ChannelError):
    """A timeout was reached while reading or writing a channel.

    :param data: the data read before the timeout occurred
    :type data: bytes
    """

    def __init__(self, ch, data: bytes):
        super().__init__(ch, f"channel recieve timed out: {repr(data)}")
        self.data: bytes = data


class ChannelFile(RawIOBase):
    """
    Wrap a channel in a file-like object. Mainly used for process IO by
    the platform wrappers. It enables platforms to quickly create a file-like
    object which is bounded by a delimeter and can be returned to the user
    safely. You will not normally create this class directly, but should use
    the func:`Channel.makefile`` method instead.

    :param channel: the channel to which we bind the file
    :type channel: Channel
    :param mode: a file mode (e.g. "r" or "w")
    :type mode: str
    :param sof: start of file delimeter; we will recv until this before returning.
    :type sof: Optional[bytes]
    :param eof: end of file delimeter; eof will be set after seeing this bytestr
    :type eof: Optional[bytes]
    :param on_close: a method to call before closing the file
    :type on_close: Callable[[Channel], None]
    """

    def __init__(
        self,
        channel: "Channel",
        mode: str,
        sof: Optional[bytes] = None,
        eof: Optional[bytes] = None,
        on_close=None,
    ):
        self.channel = channel
        self.mode = mode
        self.sof_marker = sof
        self.eof_marker = eof
        self.found_sof = False
        self.on_close = on_close
        self.eof = False
        self._blocking = True

        if self.sof_marker is not None and "r" in self.mode:
            self.channel.recvuntil(self.sof_marker)
            self.found_sof = True

    @property
    def blocking(self) -> bool:
        """Indicates whether to act like a blocking file or not."""
        return self._blocking

    @blocking.setter
    def blocking(self, value):
        self._blocking = value

    def readable(self) -> bool:
        """Test if this is a readable file."""
        return "r" in self.mode

    def writable(self) -> bool:
        """Test if this is writable file."""
        return "w" in self.mode

    def close(self):
        """Close the file for reading/writing. This method calls the on_close hook."""

        if self.eof:
            return

        self.eof = True

        if self.on_close is not None:
            self.on_close(self)

    def readall(self):
        """Read all data until EOF"""

        data = b""

        while not self.eof:
            new_data = self.read(4096)
            if new_data is None:
                continue
            data += new_data

        return data

    def readinto(self, b: Union[memoryview, bytearray]):
        """Read as much data as possible into the given bytearray or memory view.

        :param b: the buffer data into
        :type b: Union[memoryview, bytearray]
        """

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

            if n == 0 and not self.blocking:
                return None

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
        """Write the given data to the channel

        :param data: the data to write to the channel
        :type data: bytes
        """

        if self.eof:
            return 0

        written = 0
        while written < len(data):
            written += self.channel.send(data)

        return written


class Channel(ABC):
    """
    Abstract interation with a remote victim. This class acts similarly to a
    socket object. In the common cases, it simply wraps a socket object. Some
    methods have default implementations, but many are required to be implemented.
    At a minimum, the following methods/properties must be implemented:

    - connected
    - send
    - recv
    - recvinto
    - drain
    - close

    The ``peek`` and ``unrecv`` methods have default implementations which buffer some
    data in memory. If using the default implementations of these methods, you should
    be prepared to read first from `self.peek_buffer` prior to making downstream recv
    requests.

    In general, direct connections are made during ``__init__``. If you are implementing
    a listener, the ``connect`` method can be used to wait for/accept the final
    connection. It is called just before instantiating the resulting pwncat session.
    At all times, ``connected`` should reflect the state of the underlying data channel.
    In the case of listeners, ``connected`` should only be true after ``connect`` is
    called. The ``close`` method should set ``connected`` to false.

    During initialization, you can take any keyword arguments you require to connect.
    However, you should also always accept a ``**kwargs`` argument. Parameters are
    passed dynamically from ``pwncat.channel.create`` and may be attempted with extra
    arguments you don't need.
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
    @abstractmethod
    def connected(self):
        """Check if this channel is connected. This should return
        false prior to an established connection, and may return
        true prior to the ``connect`` method being called for some
        channel types."""

    def connect(self):
        """Utilize the parameters provided at initialization to
        connect to the remote host. This is mainly used for channels
        which listen for a connection. In that case, `__init__` creates
        the listener while connect actually establishes a connection.
        For direct connection-type channels, all logic can be implemented
        in the constructor.

        This method is called when creating a platform around this channel
        to instantiate the session.
        """

    @abstractmethod
    def send(self, data: bytes):
        """Send data to the remote shell. This is a blocking call
        that only returns after all data is sent.

        :param data: the data to send to the victim
        :type data: bytes
        :rtype: None
        """

    def sendline(self, data: bytes, end: bytes = b"\n"):
        """Send data followed by an ending character. If no ending
        character is specified, a new line is used. This is a blocking
        call.

        :param data: the data to send to the victim
        :type data: bytes
        :param end: the bytes to append
        :type end: bytes
        :rtype: None
        """

        return self.send(data + end)

    @abstractmethod
    def recv(self, count: Optional[int] = None) -> bytes:
        """Receive data from the remote shell

        If your channel class does not implement ``peek``, a default
        implementation is provided. If you provide a custom recv, but
        use the default :func:`peek` you must return data from
        ``self.peek_buffer`` prior to call ``recv``.

        :param count: maximum number of bytes to receive (default: unlimited)
        :type count: int
        :return: the data that was received
        :rtype: bytes
        """

    def drain(self):
        """Drain any buffered data until there is nothing left"""

        while True:
            data = self.recv(4096)
            if data is None or len(data) == 0:
                break

    def recvuntil(self, needle: bytes, timeout: Optional[float] = None) -> bytes:
        """Receive data until the specified string of bytes is found
        is found. The needle is not stripped from the data. This is a
        default implementation which utilizes the ``recv`` method.
        You can override this if your underlying transport provides a
        better implementation.

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
                raise ChannelTimeout(self, data)

            next_byte = self.recv(1)

            if next_byte is not None:
                data += next_byte

        return data

    def recvline(self, timeout: Optional[float] = None) -> bytes:
        """Recieve data until a newline is received. The newline
        is not stripped. This is a default implementation that
        utilizes the ``recvuntil`` method.

        :param timeout: a timeout in seconds for the recv
        :type timeout: float
        :rtype: bytes
        """

        return self.recvuntil(b"\n", timeout=timeout)

    def peek(self, count: Optional[int] = None, timeout: Optional[float] = None):
        """Receive data from the victim and leave the data in the recv
        buffer. This is a default implementation which uses an internal
        ``bytes`` buffer within the channel to simulate a peek. You can
        override this method if your underlying transport supports real
        ``peek`` operations. If the default ``peek`` implementation is
        used, ``recv`` should read ``self.peek_buffer`` prior to calling
        the underlying ``recv``.

        The ``timeout`` argument works differently from other methods.
        If no timeout is specified, then the method returns immediately
        and may return no data. If a timeout is provided, then the method
        will wait up to ``timeout`` seconds for at least one byte of data
        not to exceed ``count`` bytes.

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

        if count is not None:
            count -= len(data)

        if timeout is not None:
            end_time = time.time() + timeout
        else:
            end_time = 0

        while True:
            self.peek_buffer = b""
            new_data = self.recv(count)
            count -= len(new_data)
            data += new_data
            if len(data) or timeout is None:
                break
            if timeout is not None and time.time() > end_time:
                break
            time.sleep(0.1)

        self.peek_buffer = data

        return data

    def unrecv(self, data: bytes):
        """
        Place the given bytes on a buffer to be returned next by recv.
        This method utilizes the internal ``peek`` buffer. Therefore,
        if you implement a custom ``peek`` method, you must also implement
        ``unrecv``.

        :param data: the data to place on the incoming buffer
        :type data: bytes
        :rtype: None
        """

        # This makes the next recv return this data first
        self.peek_buffer = data + self.peek_buffer

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

    def recvinto(self, b):
        raise NotImplementedError

    @abstractmethod
    def close(self):
        """Close this channel. This method should do nothing if
        the ``connected`` property returns False."""

    def __str__(self):
        """Get a representation of this channel. The resulting string
        will be passed through ``rich`` output, so it can contain tags
        to affect styling and/or color. The default implementation returns
        ``remote_address:remote_port``"""

        return f"[cyan]{self.address[0]}[/cyan]:[blue]{self.address[1]}[/blue]"


def register(name: str, channel_class: Type[Channel]):
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


def create(protocol: Optional[str] = None, **kwargs) -> Channel:
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
            if (
                "host" not in kwargs
                or kwargs["host"] == "0.0.0.0"
                or kwargs["host"] is None
            ):
                if "certfile" in kwargs or "keyfile" in kwargs:
                    protocols.append("ssl-bind")
                else:
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


from pwncat.channel.ssh import Ssh  # noqa: E402
from pwncat.channel.bind import Bind  # noqa: E402
from pwncat.channel.socket import Socket  # noqa: E402
from pwncat.channel.connect import Connect  # noqa: E402
from pwncat.channel.ssl_bind import SSLBind  # noqa: E402

register("socket", Socket)
register("bind", Bind)
register("connect", Connect)
register("ssh", Ssh)
register("ssl-bind", SSLBind)
