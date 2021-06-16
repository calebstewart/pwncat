"""
A platform is the pwncat abstraction for an OS or specific distribution. In general,
this abstraction allows pwncat to generically interact with targets at the OS level.
For example, a platform provides a ``pathlib.Path`` implementation which provides
seamless file access. A platform also defines ways to query environment variables,
get the current user ID and name and generically start processes.

An individual platform must define a set of methods within it's ``Platform`` class
for file abstraction, process abstraction, and user abstraction. These methods are
then used by the generic ``Path`` and ``Popen`` classes to abstract interaction
with the target.

Normally, you can access a platform through a session. Every session has a platform
property which returns a platform-specific implementation of the core methods outlined
below.

pathlib-like File Abstraction
-----------------------------

Each platform sets the ``Path`` property to a class which glues our generic ``Path``
class below to either ``PureWindowsPath`` or ``PureLinuxPath``. You can construct
a session-specific path object by utilizing the ``session.platform.Path`` property.

.. code-block:: python

    path = session.platform.Path("/etc/passwd")
    print(path.read_text())

"""
import os
import sys
import stat
import fnmatch
import logging
import threading
import logging.handlers
from abc import ABC, abstractmethod
from typing import List, Type, Union, BinaryIO, Optional, Generator
from subprocess import CalledProcessError

from rich.logging import RichHandler

import pwncat
import pwncat.channel
import pwncat.subprocess

PLATFORM_TYPES = {}
""" A dictionary of platform names mapping to their class
objects. This drives the ``pwncat.platform.create`` factory
function. """


class PlatformError(Exception):
    """Generic platform error."""


class Path:
    """
    A Concrete-Path. An instance of this class is bound to a
    specific victim, and supports all semantics of a standard
    pathlib concrete Path.
    """

    _target: "Platform"
    _stat: os.stat_result
    _lstat: os.stat_result
    parts = []

    @classmethod
    def cwd(cls) -> "Path":
        """Return a new concrete path referencing the current directory"""
        return cls(".").resolve()

    @classmethod
    def home(cls) -> "Path":
        """Return a new concrete path referencing the current user home directory"""
        return cls("~").resolve()

    def writable(self) -> bool:
        """Test if this file is writable based on the stat results
        and the sessions current user/group ID."""

        user = self._target.session.current_user()
        group = self._target.session.find_group(gid=user.gid)
        mode = self.stat().st_mode
        uid = self.stat().st_uid
        gid = self.stat().st_gid

        if uid == user.id and (mode & stat.S_IWUSR):
            return True
        elif group.id == gid and (mode & stat.S_IWGRP):
            return True
        else:
            if group.id == gid and (mode & stat.S_IWGRP):
                return True
            else:
                if mode & stat.S_IWOTH:
                    return True

        return False

    def readable(self) -> bool:
        """Test if this file is readable based on the stat results and
        the sessions' current user/group ID."""

        user = self._target.session.current_user()
        group = self._target.session.find_group(gid=user.gid)
        mode = self.stat().st_mode
        uid = self.stat().st_uid
        gid = self.stat().st_gid

        if uid == user.id and (mode & stat.S_IRUSR):
            return True
        elif group.id == gid and (mode & stat.S_IRGRP):
            return True
        else:
            if group.id == gid and (mode & stat.S_IRGRP):
                return True
            else:
                if mode & stat.S_IROTH:
                    return True

        return False

    def stat(self) -> os.stat_result:
        """Request file stat details"""

        if self._stat is not None:
            return self._stat

        self._stat = self._target.stat(str(self))

        return self._stat

    def chmod(self, mode: int):
        """Modify file unix permissions

        :param mode: unix permission bits
        :type mode: int
        """

        self._target.chmod(str(self), mode)

    def exists(self) -> bool:
        """Test if the path exists on the target system"""

        try:
            self.stat()
            return True
        except FileNotFoundError:
            return False

    def expanduser(self) -> "Path":
        """Return a new path object which represents the full path to the file
        expanding any ``~`` or ``~user`` components."""

        if not self.parts[0].startswith("~"):
            return self.__class__(self)

        if self.parts[0] == "~":
            return self.__class__(
                self._target.find_user(self._target.whoami()).homedir, *self.parts[1:]
            )
        else:
            return self.__class__(
                self._target.find_user(self.parts[0][1:]).homedir, *self.parts[1:]
            )

    def glob(self, pattern: str) -> Generator["Path", None, None]:
        """Glob the given relative pattern in the directory represented
        by this path, yielding Path objects for any matching files/directories."""

        for name in self._target.listdir(str(self)):
            if fnmatch.fnmatch(name, pattern):
                yield self / name

    def group(self) -> str:
        """Returns the name of the group owning the file. KeyError is raised
        if the file's GID isn't found in the system database."""

        return self._target.session.find_group(gid=self.stat().st_gid).name

    def is_dir(self) -> bool:
        """Returns True if the path points to a directory (or a symbolic link
        pointing to a directory). False if it points to another kind of file.
        """

        try:
            return stat.S_ISDIR(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_file(self) -> bool:
        """Returns True if the path points to a regular file"""

        try:
            return stat.S_ISREG(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_mount(self) -> bool:
        """Returns True if the path is a mount point."""

        if str(self) == "/":
            return True

        if self.parent.stat().st_dev != self.stat().st_dev:
            return True

        return False

    def is_symlink(self) -> bool:
        """Returns True if the path points to a symbolic link, False otherwise"""

        try:
            return stat.S_ISLNK(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_socket(self) -> bool:
        """Returns True if the path points to a Unix socket"""

        try:
            return stat.S_ISSOCK(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_fifo(self) -> bool:
        """Returns True if the path points to a FIFO"""

        try:
            return stat.S_ISFIFO(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_block_device(self) -> bool:
        """Returns True if the path points to a block device"""

        try:
            return stat.S_ISBLK(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_char_device(self) -> bool:
        """Returns True if the path points to a character device"""

        try:
            return stat.S_ISCHR(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def iterdir(self) -> bool:
        """When the path points to a directory, yield path objects of the
        directory contents."""

        if not self.is_dir():
            raise NotADirectoryError

        for name in self._target.listdir(str(self)):
            if name == "." or name == "..":
                continue
            yield self.__class__(*self.parts, name)

    def lchmod(self, mode: int):
        """Modify a symbolic link's mode (same as chmod for non-symbolic links)"""

        self._target.chmod(str(self), mode, link=True)

    def lstat(self) -> os.stat_result:
        """Same as stat except operate on the symbolic link file itself rather
        than the file it points to."""

        if self._lstat is not None:
            return self._lstat

        self._lstat = self._target.lstat(str(self))

        return self._lstat

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False):
        """Create a new directory at this given path."""

        if not exist_ok and self.exists():
            raise FileExistsError(str(self))

        if self.exists() and not self.is_dir():
            raise FileExistsError(str(self))

        self._target.mkdir(str(self), mode=mode, parents=parents)

    def open(
        self,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = None,
        errors: str = None,
        newline: str = None,
    ):
        """Open the file pointed to by the path, like Platform.open"""

        return self._target.open(
            str(self),
            mode=mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )

    def owner(self) -> str:
        """Return the name of the user owning the file. KeyError is raised if
        the file's uid is not found in the System database"""

        return self._target.session.find_user(uid=self.stat().st_uid).name

    def read_bytes(self) -> bytes:
        """Return the binary contents of the pointed-to file as a bytes object"""

        with self.open("rb") as filp:
            return filp.read()

    def read_text(self, encoding: str = None, errors: str = None) -> str:
        """Return the decoded contents of the pointed-to file as a string"""

        with self.open("r", encoding=encoding, errors=errors) as filp:
            return filp.read()

    def readlink(self) -> "Path":
        """Return the path to which the symbolic link points"""

        return self._target.readlink(str(self))

    def rename(self, target) -> "Path":
        """Rename the file or directory to the given target (str or Path)."""

        self._target.rename(str(self), str(target))

        if not isinstance(target, self.__class__):
            return self.__class__(target)

        return target

    def replace(self, target) -> "Path":
        """Same as `rename` for Linux"""

        return self.rename(target)

    def resolve(self, strict: bool = False):
        """Resolve the current path into an absolute path"""

        return self.__class__(self._target.abspath(str(self)))

    def rglob(self, pattern: str) -> Generator["Path", None, None]:
        r"""This is like calling Path.glob() with "\*\*/" added to in the front
        of the given relative pattern"""

        return self.glob("**/" + pattern)

    def rmdir(self):
        """Remove this directory. The directory must be empty."""

        if not self.is_dir():
            raise NotADirectoryError(str(self))

        self._target.rmdir(str(self))

    def samefile(self, otherpath: "Path"):
        """Return whether this path points to the same file as other_path
        which can be either a Path object or a string."""

        if not isinstance(otherpath, Path):
            otherpath = self.__class__(otherpath)

        stat1 = self.stat()
        stat2 = otherpath.stat()

        return os.path.samestat(stat1, stat2)

    def symlink_to(self, target, target_is_directory: bool = False):
        """Make this path a symbolic link to target."""

        if not isinstance(target, self.__class__):
            target = self.__class__(target)

        if not target.exists():
            raise FileNotFoundError(str(target))

        if self.exists():
            raise FileExistsError(str(self))

        try:
            self._target.symlink_to(str(target), str(self))
        except CalledProcessError as exc:
            raise OSError(exc.stdout) from exc

    def touch(self, mode: int = 0o666, exist_ok: bool = True):
        """Createa file at this path. If the file already exists, function
        succeeds if exist_ok is true (and it's modification time is updated).
        Otherwise FileExistsError is raised."""

        existed = self.exists()

        if not exist_ok and existed:
            raise FileExistsError(str(self))

        self._target.touch(str(self))

        if not existed:
            self.chmod(mode)

    def unlink(self, missing_ok: bool = False):
        """Remove the file or symbolic link."""

        if not missing_ok and not self.exists():
            raise FileNotFoundError(str(self))

        try:
            self._target.unlink(str(self))
        except FileNotFoundError as exc:
            # In this case, we couldn't distinguish between errors
            # so, we distinguish here based on stat results
            if self.is_dir():
                raise OSError(f"Directory not empty: {str(self)}") from exc
            raise

    def link_to(self, target):
        """Create a hard link pointing to a path named target"""

        if not isinstance(target, self.__class__):
            target = self.__class__(target)

        if not target.exists():
            raise FileNotFoundError(str(target))

        if self.exists():
            raise FileExistsError(str(self))

        try:
            self._target.link_to(str(target), str(self))
        except CalledProcessError as exc:
            raise OSError(exc.stdout) from exc

    def write_bytes(self, data: bytes):
        """Open the file pointed to in bytes mode and write data to it."""

        with self.open("wb") as filp:
            filp.write(data)

    def write_text(self, data: str, encoding: str = None, errors: str = None):
        """Open the file pointed to in text mode, and write data to it."""

        with self.open("w", encoding=encoding, errors=errors) as filp:
            filp.write(data)


class Platform(ABC):
    """Abstracts interactions with a target of a specific platform.
    This includes running commands, changing directories, locating
    binaries, etc.

    During construction, the channel ``connect`` method is called
    to complete any outstanding requirements for connecting the channel.
    If the channel is not connected after this, a ``PlatformError``
    is raised.

    Platform's are not created directly, but can be instantiated
    through the manager ``create_session`` method.

    :param session: a session object to which this platform is bound
    :param channel: an open a channel with the specified platform
    :type channel: pwncat.channel.Channel
    :param log: path to a log file which logs each command executed for this platform
    :type log: str
    """

    name = None
    """ Name of this platform (e.g. "linux") """

    def __init__(
        self,
        session: "pwncat.manager.Session",
        channel: "pwncat.channel.Channel",
        log: str = None,
        verbose: bool = False,
    ):

        # This will throw a ChannelError if we can't complete the
        # connection, so we do it first.
        channel.connect()

        # Ensure everything is kosher with the channel
        if not channel.connected:
            raise PlatformError("channel connection failed")

        self.session = session
        self.channel = channel
        self.logger = logging.getLogger(str(channel))
        self.logger.setLevel(logging.DEBUG)
        self.name = "unknown"
        self._current_user = None

        # output log to a file
        if log is not None:
            handler = logging.handlers.RotatingFileHandler(
                log, maxBytes=1024 * 1024 * 100, backupCount=5
            )
            handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
            self.logger.addHandler(handler)

        if verbose:
            self.logger.addHandler(RichHandler())

        base_path = self.PATH_TYPE
        target = self

        class RemotePath(base_path, Path):

            _target = target
            _stat = None

            def __init__(self, *args):
                base_path.__init__(*args)

        self.Path = RemotePath
        """ A concrete Path object for this platform conforming to pathlib.Path """

    @property
    def manager(self):
        """Shortcut to accessing the manager"""
        return self.session.manager

    def interactive_loop(self, interactive_complete: "threading.Event"):
        """Handles interactive piping of data between victim and attacker. If
        the platform you are implementing does not support raw mode, you must
        override this method to support interactivity. A working example with
        the python readline module exists in the windows platform. Linux uses
        this default implementation."""

        sys.stdin
        has_prefix = False

        pwncat.util.push_term_state()

        try:
            pwncat.util.enter_raw_mode(non_block=False)
            sys.stdin.reconfigure(line_buffering=False)

            while not interactive_complete.is_set():
                data = sys.stdin.buffer.read(64)
                has_prefix = self.session.manager._process_input(data, has_prefix)

        finally:
            pwncat.util.pop_term_state()
            sys.stdin.reconfigure(line_buffering=False)

    def process_output(self, data):
        """Called during interactivity to handle output from the victim. It can
        mutate the output and return a changed value if needed. It does nothing
        by default."""

        return data

    def __str__(self):
        """Retrieve a string describing the platform connection"""
        return str(self.channel)

    @abstractmethod
    def exit(self):
        """Exit this session"""

    @abstractmethod
    def refresh_uid(self) -> Union[int, str]:
        """Refresh the cached UID of the current session."""

    @abstractmethod
    def getuid(self) -> Union[int, str]:
        """Get the current user ID. This should not query the target, but should
        return the current cached UID as found with `refresh_uid`."""

    @abstractmethod
    def getenv(self, name: str) -> str:
        """Get the value of an environment variable.

        :param name: the name of the environment variable
        :type name: str
        :rtype: str
        """

    @abstractmethod
    def stat(self, path: str) -> os.stat_result:
        """Run stat on a path on the remote system and return a stat result
        This is mainly used by the concrete Path type to fill in a majority
        of it's methods. If the specified path does not exist or cannot be
        accessed, a FileNotFoundError or PermissionError is raised respectively

        :param path: path to a remote file
        :type path: str
        """

    @abstractmethod
    def lstat(self, path: str) -> os.stat_result:
        """Run stat on the symbolic link and return a stat result object.
        This has the same semantics as the `stat` method."""

    @abstractmethod
    def abspath(self, path: str) -> str:
        """Attempt to resolve a path to an absolute path"""

    @abstractmethod
    def readlink(self, path: str):
        """Attempt to read the target of a link"""

    @abstractmethod
    def whoami(self):
        """Retrieve's only name of the current user (may be faster depending
        on platform)"""

    @abstractmethod
    def listdir(self, path=None) -> Generator[str, None, None]:
        """List the contents of a directory. If ``path`` is None,
        then the contents of the current directory is listed. The
        list is not guaranteed to be sorted in any way.

        :param path: the directory to list
        :type path: str or Path-like
        :raise FileNotFoundError: When the requested directory is not a directory,
          does not exist, or you do not have execute permissions.
        """

    @abstractmethod
    def get_host_hash(self) -> str:
        """
        Retrieve a string which uniquely identifies this victim host. On Unix-like
        platforms, this retrieves the hostname and MAC addresses of any available
        network interfaces and computes a hash, which should be unique regardless of
        connection method.

        :return: a unique string (normally a hash) identifying this host
        :rtype: str
        """

    def which(self, name: str, **kwargs) -> str:
        """
        Locate the specified binary on the remote host. Normally, this is done through
        the local `which` command on the remote host (for unix-like hosts), but can be
        located by any means. The returned path string is guaranteed to exist on the
        remote host and provide the capabilities of the requested binary.

        :param name: name of the binary (e.g. "tar" or "dd")
        :type name: Union[list, str]
        :return: full path to the requested binary
        :rtype: str
        :raises: FileNotFoundError: the requested binary does not exist on this host
        """

        """
        TODO: We should do something about the `which` statement that is sometimes
        passed in, if we were using busybox.
        """

        if not isinstance(name, str):
            for n in name:
                path = self.which(n)
                if path is not None:
                    return path
            return None

        if name in self.session.target.utilities:
            return self.session.target.utilities[name]

        path = self._do_which(name)
        # self.session.db.transaction_manager.begin()
        self.session.target.utilities[name] = path
        self.session.db.transaction_manager.commit()

        return path

    @abstractmethod
    def _do_which(self, name: str) -> Optional[str]:
        """
        This is stub method which must be implemented by the platform. It is
        guaranteed to request to results directly from the victim whereas the
        `which` method will query the database first for cached items. It
        should not be invoked directly, but will be indirectly invoked when
        needed by `which`
        """

    def compile(
        self,
        sources: List[Union[str, BinaryIO]],
        output: str = None,
        suffix: str = None,
        cflags: List[str] = None,
        ldflags: List[str] = None,
    ) -> str:
        """
        Attempt to compile the given C source files into a binary suitable for the remote
        host. If a compiler exists on the remote host, prefer compilation locally. If no
        compiler exists on the remote remote host, check the `cross` global config variable
        for the path to a local compiler capable of generating binaries for the remote host.
        If the binary is compiled locally, it is automatically uploaded to the remote host.
        The path to the new binary on the victim is returned.

        :param sources: list of source file paths or IO streams used as source files
        :type sources: List[Union[str, io.IOBase]]
        :param output: base name of the output file. If not specified, a name is randomly generated.
        :type output: str
        :param suffix: a suffix to add to the output name.
        :type suffix: str
        :param cflags: a list of flags to pass to the compiler
        :type cflags: List[str]
        :param ldflags: a list of flags to pass to the linker
        :type ldflags: List[str]
        :return: str
        :raises NotImplementedError: this platform does not support c compilation
        :raises PlatformError: no local or cross compiler detected or compilation failed
        """

        raise NotImplementedError(f"no C compilation support available on {self.name}")

    @abstractmethod
    def Popen(
        self,
        args,
        stdin=None,
        stdout=None,
        stderr=None,
        shell=False,
        cwd=None,
        encoding=None,
        errors=None,
        text=None,
        env=None,
        universal_newlines=None,
        **other_popen_kwargs,
    ) -> pwncat.subprocess.Popen:
        """
        Execute a process on the remote host with an interface similar to
        that of the python standard ``subprocess.Popen``. The returned
        object behaves much like a standard ``Popen`` object and conforms
        to the interface defined by ``pwncat.subprocess.Popen``. For
        an explanation of arguments, see ``pwncat.subprocess.Popen``.
        """

    def run(
        self,
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
        popen_class=None,
        **other_popen_kwargs,
    ) -> pwncat.subprocess.Popen:
        """
        Run the given command utilizing the ``self.popen`` method and
        return a ``pwncat.subprocess.CompletedProcess`` instance.
        """

        if capture_output:
            stdout = pwncat.subprocess.PIPE
            stderr = pwncat.subprocess.PIPE

        if input is not None:
            stdin = pwncat.subprocess.PIPE

        if popen_class is None:
            popen_class = self.Popen

        p = popen_class(
            args,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            shell=shell,
            cwd=cwd,
            encoding=encoding,
            text=text,
            errors=errors,
            env=env,
            **other_popen_kwargs,
        )

        stdout, stderr = p.communicate(input=input, timeout=timeout)

        completed_proc = pwncat.subprocess.CompletedProcess(
            args, p.returncode, stdout, stderr
        )

        if check:
            completed_proc.check_returncode()

        return completed_proc

    @abstractmethod
    def chdir(self, path: Union[str, Path]):
        """
        Change directories to the given path. This method returns the current
        working directory prior to the change.

        :param path: a relative or absolute path to change to
        :type path: Union[str, Path]
        :return: current working directory prior to the change
        :raises:
          FileNotFoundError: the specified path doesn't exist
          NotADirectoryError: the specified path is not a directory
        """

    @abstractmethod
    def open(self, path: Union[str, Path], mode: str):
        """
        Open a remote file for reading or writing. Normally, only one of read or
        write modes are allowed for a remote file, but this may change with
        future platforms. It is recommended to only use one mode when opening
        remote files. This method attempts to replicate the built-in ``open``
        function and returns a file-like object. The `b` mode is honored and
        if not present, a TextIOWrapper is used to wrap the file object to ensure
        text data is returned.

        :param path: path to the file
        :type path: Union[str, Path]
        :param mode: the open-mode (see built-in ``open``)
        :type mode: str
        :return: a file-like object
        :raises:
          FileNotFoundError: the specified file does not exist
          IsADirectoryError: the specified path refers to a directory
        """

    @abstractmethod
    def tempfile(
        self, mode: str, length: Optional[int] = None, suffix: Optional[str] = None
    ):
        """
        Create a temporary file on the remote host and open it with the specified mode.
        Creating a new temporary file with a mode other than "w" is mostly useless,
        however ``mode`` can be used to specify a binary or text-mode file. The length
        argument is useful if you know the length of file you are about to read. This
        alleviates some situations which could be complicated on some platforms by not
        knowing the intended file length prior to opening. Optionally, a suffix can be
        added to the random file name. A file-like object is returned. The temporary
        file is not removed by pwncat itself. Unless explicitly removed, it will continue
        to exist until the remote operating system cleans up temporary files (possible
        at the next reboot).

        :param mode: the open-mode for the new file-like object
        :type mode: str
        :param length: the intended length for the new file
        :type length: int
        :param suffix: a suffix for the filename
        :type suffix: str
        :return: a file-like object
        """

    def su(self, user: str, password: Optional[str] = None):
        """
        Attempt to switch users in the running shell. This normally executes a new
        sub-shell as the requested user. On unix-like systems, this is simply a
        wrapper for the ``su`` command. Implementations may differ on other systems.
        If a password isn't provided, the database will be consulted for a matching
        username and password.

        :param user: the name of the new user
        :type user: str
        :param password: the password for the new user
        :type password: str
        :raises:
          PermissionError: the provided password was incorrect
        """

        raise NotImplementedError(
            f"switch-user not implemented for platform {self.name}"
        )

    def sudo(
        self,
        command: Union[str, List[str]],
        user: Optional[str] = None,
        group: Optional[str] = None,
        **popen_kwargs,
    ):
        """
        Run the specified command as the specified user and group. On unix-like systems
        the normally translates to the ``sudo`` command. The command is executed using
        the ``self.popen`` method. All arguments not documented here are passed directly
        to ``self.popen``. The process is executed and if a password is required, it is
        sent from the database. If a password is not available, the process is killed
        and a PermissionError is raised. If the password is incorrect, a PermissionError
        is also raised.
        """

        raise NotImplementedError(f"sudo not implemented for platform {self.name}")

    @abstractmethod
    def umask(self, mask: int = None):
        """Set or retrieve the current umask value"""

    @abstractmethod
    def touch(self, path: str):
        """Update a file modification time and possibly create it"""

    @abstractmethod
    def chmod(self, path: str, mode: int, link: bool = False):
        """Update the file permissions"""

    @abstractmethod
    def mkdir(self, path: str, mode: int = 0o777, parents: bool = False):
        """Create a new directory"""

    @abstractmethod
    def rename(self, source: str, target: str):
        """Rename a file from the source to the target. This should
        replace the target if it exists."""

    @abstractmethod
    def rmdir(self, target: str):
        """Remove the specified directory. It must be empty."""

    @abstractmethod
    def symlink_to(self, source: str, target: str):
        """Create a symbolic link to source from target"""

    @abstractmethod
    def link_to(self, source: str, target: str):
        """Create a filesystem hard link."""

    @abstractmethod
    def unlink(self, target: str):
        """Remove a link to a file (similar to `rm`)"""


def register(platform: Type[Platform]):
    """
    Register a platform class to be automatically constructed with the
    ``create`` factory function with the given name. This can be used
    to register new custom platforms in plugins.

    :param name: the name of the new platform
    :type name: str
    :param platform: the platform class
    :type platform: Type[Platform]
    """

    global PLATFORM_TYPES

    PLATFORM_TYPES[platform.name] = platform


def find(name: str) -> Type[Platform]:
    """
    Retrieve the platform class for the specified name

    :param name: name of the platform
    :type name: str
    :return: the platform class
    :rtype: Type[Platform]
    :raises: KeyError: if the specified platform does not exist
    """

    global PLATFORM_TYPES

    return PLATFORM_TYPES[name]


def create(
    platform: str,
    log: str = None,
    channel: Optional[pwncat.channel.Channel] = None,
    **kwargs,
):
    """
    Create a new platform object with a registered platform type.
    If no channel is specified, then this will attempt to utilize
    the ``pwncat.channel.create`` factory function to create a
    channel. In this case, all keyword arguments are passed to the
    channel creation function and a platform is created around the
    channel.

    :param platform: the name of the platform to construct
    :type platform: str
    :param channel: the C2 channel to use for communication
    :type channel: pwncat.channel.Channel
    :return: A newly created platform around the specified channel
    :rtype: Platform
    :raises:
      KeyError: if the specified platform does not exist
      ChannelError: if a channel could not be created
    """

    if channel is None:
        channel = pwncat.channel.create(**kwargs)

    return find(platform)(channel, log)


from pwncat.platform.linux import Linux  # noqa: E402
from pwncat.platform.windows import Windows  # noqa: E402

register(Linux)
register(Windows)
