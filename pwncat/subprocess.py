"""
This provides a subprocess-compatible definition of an internal pwncat
Popen object. A pwncat Popen object wraps a remote process in a local
manager which provides an almost-identical interface as the builtin
subprocess module.

.. note::

    Depending on the platform you are connected to, you may only be
    able to run a single process at a time. Because of this, you
    should always ensure the process properly exits and you call
    ``Popen.wait()`` or recieve a non-None result from ``Popen.poll()``
    before calling other pwncat methods.

"""
from typing import IO, List, Optional
from subprocess import (  # noqa: F401
    PIPE,
    DEVNULL,
    TimeoutExpired,
    SubprocessError,
    CompletedProcess,
    CalledProcessError,
)


class Popen:
    """Base class for Popen objects defining the interface.
    Individual platforms will subclass this object to implement
    the correct logic. This is an abstract class."""

    stdin: IO
    """
    If the stdin argument was PIPE, this attribute is a writeable
    stream object as returned by open(). If the encoding or errors
    arguments were specified or the universal_newlines argument was
    True, the stream is a text stream, otherwise it is a byte
    stream. If the stdin argument was not PIPE, this attribute is
    None.
    """
    stdout: IO
    """
    If the stdout argument was PIPE, this attribute is a readable
    stream object as returned by open(). Reading from the stream
    provides output from the child process. If the encoding or
    errors arguments were specified or the universal_newlines
    argument was True, the stream is a text stream, otherwise it
    is a byte stream. If the stdout argument was not PIPE, this
    attribute is None.
    """
    stderr: IO
    """
    If the stderr argument was PIPE, this attribute is a readable
    stream object as returned by open(). Reading from the stream
    provides error output from the child process. If the encoding
    or errors arguments were specified or the universal_newlines
    argument was True, the stream is a text stream, otherwise it
    is a byte stream. If the stderr argument was not PIPE, this
    attribute is None.
    """
    args: List[str]
    """
    The args argument as it was passed to Popen – a sequence of
    program arguments or else a single string.
    """
    pid: int
    """ The process ID of the child process. """
    returncode: int
    """
    The child return code, set by poll() and wait() (and indirectly by
    communicate()). A None value indicates that the process hasn’t
    terminated yet.
    """

    def __init__(self):
        self.pid = None
        self.returncode = None
        self.args = None
        self.stderr = None
        self.stdout = None
        self.stdin = None

    def poll(self) -> Optional[int]:
        """Check if the child process has terminated. Set and return
        ``returncode`` attribute. Otherwise, returns None."""

    def wait(self, timeout: float = None) -> int:
        """Wait for child process to terminate. Set and return
        ``returncode`` attribute.

        If the process does not terminate after ``timeout`` seconds,
        raise a ``TimeoutExpired`` exception. It is safe to catch
        this exception and retry the wait.
        """

    def communicate(self, input: bytes = None, timeout: float = None):
        """Interact with process: Send data to stdin. Read data from stdout
        and stderr, until end-of-file is readched. Wait for the process to
        terminate and set the ``returncode`` attribute. The optional ``input``
        argument should be data to be sent to the child process, or None, if
        no data should be sent to the child. If streams were opened in text mode,
        ``input`` must be a string. Otherwise, it must be ``bytes``."""

    def send_signal(self, signal: int):
        """Sends the signal ``signal`` to the child.

        Does nothing if the process completed.
        """

    def terminate(self):
        """Stop the child."""

    def kill(self):
        """Kills the child"""
