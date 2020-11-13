#!/usr/bin/env python3
from typing import List, Optional, Generator, Union, BinaryIO, Type
from subprocess import CalledProcessError
import enum
import pathlib
import logging
import logging.handlers
import fnmatch
import stat
import os

import pwncat
import pwncat.subprocess
import pwncat.channel

PLATFORM_TYPES = {}
""" A dictionary of platform names mapping to their class
objects. This drives the ``pwncat.platform.create`` factory
function. """


class PlatformError(Exception):
    """ Generic platform error. """


class Path:
    """
    A Concrete-Path. An instance of this class is bound to a
    specific victim, and supports all semantics of a standard
    pathlib concrete Path with the exception of `Path.home` and
    `Path.cwd`.
    """

    _target: "Platform"
    _stat: os.stat_result
    _lstat: os.stat_result
    parts = []

    def writable(self) -> bool:
        """ This is non-standard, but is useful """

        user = self._target.current_user()
        mode = self.stat().st_mode
        uid = self.stat().st_uid
        gid = self.stat().st_gid

        if uid == user.id and (mode & stat.S_IWUSR):
            return True
        elif user.group.id == gid and (mode & stat.S_IWGRP):
            return True
        else:
            for group in user.groups:
                if group.id == gid and (mode & stat.S_IWGRP):
                    return True
            else:
                if mode & stat.S_IWOTH:
                    return True

        return False

    def stat(self) -> os.stat_result:
        """ Run `stat` on the path and return a stat result """

        if self._stat is not None:
            return self._stat

        self._stat = self._target.stat(str(self))

        return self._stat

    def chmod(self, mode: int):
        """ Execute `chmod` on the remote file to change permissions """

        self._target.chmod(str(self), mode)

    def exists(self) -> bool:
        """ Return true if the specified path exists on the remote system """

        try:
            self.stat()
            return True
        except FileNotFoundError:
            return False

    def expanduser(self) -> "Path":
        """ Return a new path object with ~ and ~user expanded """

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
        """ Glob the given relative pattern in the directory represented
        by this path, yielding all matching files (of any kind) """

        for name in self._target.listdir(str(self)):
            if fnmatch.fnmatch(name, pattern):
                yield self / name

    def group(self) -> str:
        """ Returns the name of the group owning the file. KeyError is raised
        if the file's GID isn't found in the system database. """

        return self._target.find_group(id=self.stat().st_gid).name

    def is_dir(self) -> bool:
        """ Returns True if the path points to a directory (or a symbolic link
        pointing to a directory). False if it points to another kind of file.
        """

        try:
            return stat.S_ISDIR(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_file(self) -> bool:
        """ Returns True if the path points to a regular file """

        try:
            return stat.S_ISREG(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_mount(self) -> bool:
        """ Returns True if the path is a mount point. """

        if self.parent.stat().st_dev != self.stat().st_dev:
            return True

        return False

    def is_symlink(self) -> bool:
        """ Returns True if the path points to a symbolic link, False otherwise """

        try:
            return stat.S_ISLNK(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_socket(self) -> bool:
        """ Returns True if the path points to a Unix socket """

        try:
            return stat.S_ISSOCK(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_fifo(self) -> bool:
        """ Returns True if the path points to a FIFO """

        try:
            return stat.S_ISFIFO(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_block_device(self) -> bool:
        """ Returns True if the path points to a block device """

        try:
            return stat.S_ISBLK(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def is_char_device(self) -> bool:
        """ Returns True if the path points to a character device """

        try:
            return stat.S_ISCHR(self.stat().st_mode)
        except (FileNotFoundError, PermissionError):
            return False

    def iterdir(self) -> bool:
        """ When the path points to a directory, yield path objects of the
        directory contents. """

        if not self.is_dir():
            raise NotADirectoryError

        for name in self._target.listdir(str(self)):
            if name == "." or name == "..":
                continue
            yield self.__class__(*self.parts, name)

    def lchmod(self, mode: int):
        """ Modify a symbolic link's mode (same as chmod for non-symbolic links) """

        self._target.chmod(str(self), mode, link=True)

    def lstat(self) -> os.stat_result:
        """ Same as stat except operate on the symbolic link file itself rather
        than the file it points to. """

        if self._lstat is not None:
            return self._lstat

        self._lstat = self._target.lstat(str(self))

        return self._lstat

    def mkdir(self, mode: int = 0o777, parents: bool = False, exist_ok: bool = False):
        """ Create a new directory at this given path. """

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
        """ Open the file pointed to by the path, like Platform.open """

        return self._target.open(
            self,
            mode=mode,
            buffering=buffering,
            encoding=encoding,
            errors=errors,
            newline=newline,
        )

    def owner(self) -> str:
        """ Return the name of the user owning the file. KeyError is raised if
        the file's uid is not found in the System database """

        return self._target.find_user(id=self.stat().st_uid).name

    def read_bytes(self) -> bytes:
        """ Return the binary contents of the pointed-to file as a bytes object """

        with self.open("rb") as filp:
            return filp.read()

    def read_text(self, encoding: str = None, errors: str = None) -> str:
        """ Return the decoded contents of the pointed-to file as a string """

        with self.open("r", encoding=encoding, errors=errors) as filp:
            return filp.read()

    def readlink(self) -> "Path":
        """ Return the path to which the symbolic link points """

        return self._target.readlink(str(self))

    def rename(self, target) -> "Path":
        """ Rename the file or directory to the given target (str or Path). """

        self._target.rename(str(self), str(target))

        if not isinstance(target, self.__class__):
            return self.__class__(target)

        return target

    def replace(self, target) -> "Path":
        """ Same as `rename` for Linux """

        return self.rename(target)

    def resolve(self, strict: bool = False):
        """ Resolve the current path into an absolute path """

        return self.__class__(self._target.abspath(str(self)))

    def rglob(self, pattern: str) -> Generator["Path", None, None]:
        """ This is like calling Path.glob() with "**/" added to in the front
        of the given relative pattern """

        return self.glob("**/" + pattern)

    def rmdir(self):
        """ Remove this directory. The directory must be empty. """

        if not self.is_dir():
            raise NotADirectoryError(str(self))

        self._target.rmdir(str(self))

    def samefile(self, otherpath: "Path"):
        """ Return whether this path points to the same file as other_path
        which can be either a Path object or a string. """

        if not isinstance(otherpath, Path):
            otherpath = self.__class__(otherpath)

        stat1 = self.stat()
        stat2 = otherpath.stat()

        return os.path.samestat(stat1, stat2)

    def symlink_to(self, target, target_is_directory: bool = False):
        """ Make this path a symbolic link to target. """

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
        """ Createa file at this path. If the file already exists, function
        succeeds if exist_ok is true (and it's modification time is updated).
        Otherwise FileExistsError is raised. """

        existed = self.exists()

        if not exist_ok and existed:
            raise FileExistsError(str(self))

        self._target.touch(str(self))

        if not existed:
            self.chmod(mode)

    def unlink(self, missing_ok: bool = False):
        """ Remove the file or symbolic link. """

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
        """ Create a hard link pointing to a path named target """

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
        """ Open the file pointed to in bytes mode and write data to it. """

        with self.open("wb") as filp:
            filp.write(data)

    def write_text(self, data: str, encoding: str = None, errors: str = None):
        """ Open the file pointed to in text mode, and write data to it. """

        with self.open("w", encoding=encoding, errors=errors) as filp:
            filp.write(data)


class Platform:
    """ Abstracts interactions with a target of a specific platform.
    This includes running commands, changing directories, locating
    binaries, etc.

    :param channel: an open a channel with the specified platform
    :type channel: pwncat.channel.Channel

    """

    def __init__(
        self,
        session: "pwncat.manager.Session",
        channel: "pwncat.channel.Channel",
        log: str = None,
    ):

        # This will throw a ChannelError if we can't complete the
        # connection, so we do it first.
        channel.connect()

        self.session = session
        self.channel = channel
        self.logger = logging.getLogger(str(channel))
        self.logger.setLevel(logging.DEBUG)
        self.name = "unknown"

        # output log to a file
        if log is not None:
            handler = logging.handlers.RotatingFileHandler(
                log, maxBytes=1024 * 1024 * 100, backupCount=5
            )
            handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
            self.logger.addHandler(handler)

        base_path = self.PATH_TYPE
        target = self

        class RemotePath(base_path, Path):

            _target = target
            _stat = None

            def __init__(self, *args):
                base_path.__init__(*args)

        self.PATH_TYPE = RemotePath

    def __str__(self):
        return str(self.channel)

    def getenv(self, name: str):
        """ Get the value of an environment variable """

    def reload_users(self):
        """ Reload the user and group cache. This is automatically called
        if the cache hasn't been built yet, but may be called manually
        if you know the users have changed. This method is also called
        if a lookup for a specific user or group ID fails. """

        raise NotImplementedError(f"{self.name} did not implement reload_users")

    def iter_users(self) -> Generator["pwncat.db.User", None, None]:
        """ Iterate over all users on the remote system """

        with self.session.db as db:
            users = db.query(pwncat.db.User).filter_by(host_id=self.session.host).all()

            if users is None:
                self.reload_users()

                users = (
                    db.query(pwncat.db.User).filter_by(host_id=self.session.host).all()
                )

            if users is not None:
                for user in users:
                    _ = user.groups
                    yield user

        return

    def find_user(
        self,
        name: Optional[str] = None,
        id: Optional[int] = None,
        _recurse: bool = True,
    ) -> "pwncat.db.User":
        """ Locate a user by name or UID. If the user/group cache has not
        been built, then reload_users is automatically called. If the
        lookup fails, reload_users is called automatically to ensure that
        there has not been a user/group update remotely. If the user
        still cannot be found, a KeyError is raised. """

        with self.session.db as db:
            user = db.query(pwncat.db.User).filter_by(host_id=self.session.host)

            if name is not None:
                user = user.filter_by(name=name)
            if id is not None:
                user = user.filter_by(id=id)

            user = user.first()
            if user is None and _recurse:
                self.reload_users()
                return self.find_user(name=name, id=id, _recurse=False)
            elif user is None:
                raise KeyError

            return user

    def current_user(self):
        """ Retrieve a user object for the current user """

        return self.find_user(name=self.whoami())

    def iter_groups(self) -> Generator["pwncat.db.Group", None, None]:
        """ Iterate over all groups on the remote system """

        with self.session.db as db:
            groups = (
                db.query(pwncat.db.Group).filter_by(host_id=self.session.host).all()
            )

            if groups is None:
                self.reload_users()

                groups = (
                    db.query(pwncat.db.Group).filter_by(host_id=self.session.host).all()
                )

            if groups is not None:
                for group in groups:
                    _ = group.members
                    yield group

        return

    def find_group(
        self,
        name: Optional[str] = None,
        id: Optional[int] = None,
        _recurse: bool = True,
    ) -> "pwncat.db.Group":
        """ Locate a group by name or GID. If the user/group cache has not
        been built, then reload_users is automatically called. If the
        lookup fails, reload_users is called automatically to ensure that
        there has not been a user/group update remotely. If the group
        still cannot be found, a KeyError is raised. """

        with self.session.db as db:
            group = db.query(pwncat.db.Group).filter_by(host_id=self.session.host)

            if name is not None:
                group = group.filter_by(name=name)
            if id is not None:
                group = group.filter_by(id=id)

            group = group.first()
            if group is None and _recurse:
                self.reload_users()
                return self.find_group(name=name, id=id, _recurse=False)
            elif group is None:
                raise KeyError

            return group

    def stat(self, path: str) -> os.stat_result:
        """ Run stat on a path on the remote system and return a stat result
        This is mainly used by the concrete Path type to fill in a majority
        of it's methods. If the specified path does not exist or cannot be
        accessed, a FileNotFoundError or PermissionError is raised respectively
        """

    def lstat(self, path: str) -> os.stat_result:
        """ Run stat on the symbolic link and return a stat result object.
        This has the same semantics as the `stat` method. """

    def abspath(self, path: str) -> str:
        """ Attempt to resolve a path to an absolute path """

    def readlink(self, path: str):
        """ Attempt to read the target of a link """

    def whoami(self):
        """ Retrieve's only name of the current user (may be faster depending
        on platform) """

    def listdir(self, path=None) -> Generator[str, None, None]:
        """ List the contents of a directory. If ``path`` is None,
        then the contents of the current directory is listed. The
        list is not guaranteed to be sorted in any way.

        :param path: the directory to list
        :type path: str or Path-like
        :raise FileNotFoundError: When the requested directory is not a directory,
          does not exist, or you do not have execute permissions.
        """

    def get_host_hash(self) -> str:
        """
        Retrieve a string which uniquely identifies this victim host. On Unix-like
        platforms, this retrieves the hostname and MAC addresses of any available
        network interfaces and computes a hash, which should be unique regardless of
        connection method.

        :return: a unique string (normally a hash) identifying this host
        :rtype: str
        """

    def which(self, name: str) -> str:
        """
        Locate the specified binary on the remote host. Normally, this is done through
        the local `which` command on the remote host (for unix-like hosts), but can be
        located by any means. The returned path string is guaranteed to exist on the
        remote host and provide the capabilities of the requested binary.

        :param name: name of the binary (e.g. "tar" or "dd")
        :type name: str
        :return: full path to the requested binary
        :rtype: str
        :raises: FileNotFoundError: the requested binary does not exist on this host
        """

    def _do_which(self, name: str) -> Optional[str]:
        """
        This is stub method which must be implemented by the platform. It is
        guaranteed to request to results directly from the victim whereas the
        `which` method will query the database first for cached items. It
        should not be invoked directly, but will be indirectly invoked when
        needed by `which`
        """

        raise NotImplementedError(f"{str(self)}: no `which` implementation")

    def compile(
        self,
        sources: List[Union[str, BinaryIO]],
        output: str = None,
        suffix: str = None,
        cflags: List[str] = None,
        ldflags: List[str] = None,
    ):
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
        """

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

        p = self.Popen(
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

    def Path(self, path: Optional[str] = None) -> Path:
        """
        Takes the given string and returns a concrete path for this host.
        This path object conforms to the "concrete path" definition of the
        standard python ``pathlib`` library. Generally speaking, it is a
        subclass of ``pathlib.PurePath`` which implements the concrete
        features by being bound to this specific victim. If no path is
        specified, a path representing the current directory is returned.

        :param path: a relative or absolute path path
        :type path: str
        :return: a concrete path object
        :rtype: Path
        """

        return self.PATH_TYPE(path)

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

    @property
    def interactive(self) -> bool:
        """
        Indicates whether the remote victim shell is currently in a state suitable for
        user-interactivity. Setting this property to True will ensure that a suitable
        shell prompt is set, echoing is one, etc.
        """

    @interactive.setter
    def interactive(self, value: bool):
        """
        Enable or disable interactivity for this victim.
        """


def register(name: str, platform: Type[Platform]):
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

    PLATFORM_TYPES[name] = platform


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


from pwncat.platform.linux import Linux

register("linux", Linux)
