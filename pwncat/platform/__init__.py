#!/usr/bin/env python3
from typing import List, Optional, Generator, Union, BinaryIO, Type
import enum
import pathlib
import logging
import logging.handlers

import pwncat
import pwncat.subprocess
import pwncat.channel

PLATFORM_TYPES = {}
""" A dictionary of platform names mapping to their class
objects. This drives the ``pwncat.platform.create`` factory
function. """


class PlatformError(Exception):
    """ Generic platform error. """


class Path(pathlib.PurePath):
    """
    A Concrete-Path. An instance of this class is bound to a
    specific victim, and supports all semantics of a standard
    pathlib concrete Path with the exception of `Path.home` and
    `Path.cwd`.
    """


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

    def path(self, path: Optional[str] = None) -> Path:
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
