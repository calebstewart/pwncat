#!/usr/bin/env python3
from typing import List, Dict, Optional, Tuple, Generator
import enum
import dataclasses


class Platform(enum.Flag):

    UNKNOWN = enum.auto()
    WINDOWS = enum.auto()
    BSD = enum.auto()
    LINUX = enum.auto()
    # This deserves some explanation.
    # This indicates that component of pwncat does not need an
    # actively connected host to be utilized. When used as a
    # module platform, it indicates that the module itself
    # only deals with the database or internal pwncat features.
    # and is allowed to run prior to a victim being connected.
    NO_HOST = enum.auto()
    ANY = WINDOWS | BSD | LINUX


class CalledProcessError(Exception):
    """ Raised when a process exits with a non-zero return code.
    This class largely mirrors ``subprocess.CalledProcessError`` class.
    """

    def __init__(self, returncode: int, args: List[str], stdout: bytes):
        super().__init__(f"Process Exited with Code {returncode}")

        self.returncode = returncode
        self.cmd = args
        self.stdout = stdout

    @property
    def output(self):
        return self.stdout


@dataclasses.dataclass
class CompletedProcess:
    """ Represents the results of a process run on the remote system.
    This largely mirrors the ``subprocess.CompletedProcess`` class.
    """

    args: List[str]
    returncode: int
    stdout: bytes

    def check_returncode(self):
        """ If ``returncode`` is none-zero, raise a CalledProcessError """
        if self.returncode != 0:
            raise CalledProcessError(self.returncode, self.args, self.stdout)


class StreamType(enum.Enum):
    """ The type of stream supplied for the stdout, stderr or stdin arguments.
    """

    PIPE = enum.auto()
    DEVNULL = enum.auto()


class Pipe:
    """ File-like object connecting to a pipe on the victim host """

    def read(self, count: int = None) -> bytes:
        """ Read data """

    def write(self, data: bytes) -> int:
        """ Write data """

    def close(self):
        """ Close the pipe """

    def isatty(self) -> bool:
        """ Check if this stream is a tty """
        return False

    def readable(self) -> bool:
        """ Check if the stream is readable """

    def writeable(self) -> bool:
        """ Check if the stream is writable """

    def seekable(self) -> bool:
        """ Remote streams are not seekable """
        return False


class Popen:
    """ Wraps running a process on the remote host. """

    def __init__(
        self,
        args: List[str],
        env: Dict[str, str] = None,
        stdout: str = None,
        stderr: str = None,
        stdin: str = None,
        shell: bool = False,
        cwd: str = None,
    ):

        return

    def poll() -> Optional[int]:
        """ Check if the process has completed """

    def communicate(self, input: bytes = None, timeout: float = None):
        """ Send data to the remote process and collect the output. """

    def terminate(self):
        """ Kill the remote process. This is sometimes not possible. """

    def kill(self):
        """ Kill the remote process. """


class _Platform:
    """ Abstracts interactions with a target of a specific platform.
    This includes running commands, changing directories, locating
    binaries, etc.

    :param channel: an open a channel with the specified platform
    :type channel: pwncat.channel.Channel

    """

    def __init__(self, channel: "pwncat.channel.Channel"):
        self.channel = channel

    def run(
        self,
        args: List[str],
        env: Dict[str, str] = None,
        stdout: str = None,
        stderr: str = None,
        stdin: str = None,
        shell: bool = False,
        cwd: str = None,
    ) -> Tuple[bytes, bytes, bytes]:
        """ Run the given command on the remote host. A tuple of three bytearrays
        is returned. These bytes are delimeters for the sections of output. The
        first delimeter is output before the command runs. The second is output
        after the command finishes, and the last is output after the return code
        is printed. """

    def chdir(self, path):
        """ Change the current working directory on the victim.
        This tracks directory changes on a stack allowing you to
        using ``pwncat.victim.popd()`` to return. """

    def listdir(self, path=None) -> Generator[str, None, None]:
        """ List the contents of a directory. If ``path`` is None,
        then the contents of the current directory is listed. The
        list is not guaranteed to be sorted in any way.

        :param path: the directory to list
        :type path: str or Path-like
        :raise FileNotFoundError: When the requested directory is not a directory,
          does not exist, or you do not have execute permissions.
        """
