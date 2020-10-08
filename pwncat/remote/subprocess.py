#!/usr/bin/env python3
from typing import List, IO, Optional
from subprocess import (
    CompletedProcess,
    SubprocessError,
    TimeoutExpired,
    CalledProcessError,
)
import io

import pwncat

DEVNULL = 0
""" Redirect to/from /dev/null or equivalent """
PIPE = 1
""" Retrieve data via a Pipe """


class PopenBase:
    """ Base class for Popen objects defining the interface.
    Individual platforms will subclass this object to implement
    the correct logic. This is an abstract class. """

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

    def poll(self) -> Optional[int]:
        """ Check if the child process has terminated. Set and return
        ``returncode`` attribute. Otherwise, returns None. """

    def wait(self, timeout: float = None) -> int:
        """ Wait for child process to terminate. Set and return
        ``returncode`` attribute.

        If the process does not terminate after ``timeout`` seconds,
        raise a ``TimeoutExpired`` exception. It is safe to catch
        this exception and retry the wait.
        """

    def communicate(self, input: bytes = None, timeout: float = None):
        """ Interact with process: Send data to stdin. Read data from stdout
        and stderr, until end-of-file is readched. Wait for the process to
        terminate and set the ``returncode`` attribute. The optional ``input``
        argument should be data to be sent to the child process, or None, if
        no data should be sent to the child. If streams were opened in text mode,
        ``input`` must be a string. Otherwise, it must be ``bytes``. """

    def send_signal(self, signal: int):
        """ Sends the signal ``signal`` to the child.

        Does nothing if the process completed.
        """

    def terminate(self):
        """ Stop the child. """

    def kill(self):
        """ Kills the child """


def Popen(*args, **kwargs) -> PopenBase:
    """ Wrapper to create a new popen object. Deligates to
    the current victim's platform ``popen`` method. """

    return pwncat.victim.popen(*args, **kwargs)


def run(
    args,
    stdin=None,
    input=None,
    stdout=None,
    stderr=None,
    capture_output=False,
    shell=False,
    cwd=None,
    timeout=None,
    check=False,
    encoding=None,
    errors=None,
    text=None,
    env=None,
    universal_newlines=None,
    **other_popen_kwargs
):
    """ Run the command described by `args`. Wait for command to complete
    and then return a CompletedProcess instance.

    The arguments are the same as the `Popen` constructor with ``capture_output``,
    ``timeout``, and ``check`` added.
    """

    # Ensure we capture standard output and standard error
    if capture_output:
        stdout = PIPE
        stderr = PIPE

    # Execute the process
    proc = Popen(
        args=args,
        stdin=stdin,
        input=input,
        stdout=stdout,
        stderr=stderr,
        shell=shell,
        cwd=cwd,
        encoding=encoding,
        errors=errors,
        text=text,
        env=env,
        universal_newlines=universal_newlines,
        **other_popen_kwargs
    )

    # Send input/receive output
    stdout_data, stderr_data = proc.communicate(input, timeout)

    # Build the completed process object
    completed_proc = CompletedProcess(args, proc.returncode, stdout_data, stderr_data)

    # Check the result
    if check:
        completed_proc.check_returncode()

    return completed_proc
