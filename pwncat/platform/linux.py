#!/usr/bin/env python3
from typing import Generator, List, Union, BinaryIO, Optional
from subprocess import CalledProcessError, TimeoutExpired
import hashlib
import time
import shlex

import pwncat
import pwncat.channel
import pwncat.platform
import pwncat.subprocess
from pwncat import util


class PopenLinux(pwncat.subprocess.Popen):
    """
    Linux-specific Popen wrapper class.
    """

    def __init__(
        self,
        platform: pwncat.platform.Platform,
        args,
        stdout,
        stdin,
        text,
        encoding,
        start_delim: bytes,
        end_delim: bytes,
        code_delim: bytes,
    ):
        super().__init__()

        self.platform: pwncat.platform.Platform = platform
        self.start_delim: bytes = start_delim
        self.end_delim: bytes = end_delim
        self.code_delim: bytes = code_delim

        # Create a reader-pipe
        if stdout == pwncat.subprocess.PIPE:
            self.stdout_pipe = True

        # We create a stdout pipe regardless. This is how we
        # track whether the process has completed.
        self.stdout = platform.channel.makefile(
            "r", sof=start_delim, eof=end_delim, text=text, encoding=encoding
        )

        # Create the writer-pipe
        if stdin == pwncat.subprocess.PIPE:
            self.stdin = platform.channel.makefile("w", text=text, encoding=encoding)

    def poll(self, _force_drain: bool = False):

        if self.returncode is not None:
            return self.returncode

        if self.stdout.eof:
            self._receive_returncode()
            return self.returncode

        # We can receive data, because the user is expecting it...
        # The only way to test whether the process is done is for the
        # user to read from the stdout or call `wait`
        if self.stdout_pipe and not _force_drain:
            return None

        # Drain buffer, don't wait for more data. The user didn't ask
        # for the data with `stdout=PIPE`, so we can safely ignore it.
        # This returns true if we hit EOF
        if self.stdout.drain():
            self._receive_returncode()
            return self.returncode

    def wait(timeout: float = None):

        if timeout is not None:
            end_time = time.time() + timeout
        else:
            end_time = None

        while self.poll(_force_drain=True) is None:
            if end_time is not None and time.time() >= end_time:
                raise TimeoutExpired(self.args, timeout)

            time.sleep(0.1)

        return self.returncode

    def communicate(self, input=None, timeout=None):

        if self.returncode is not None:
            return (None, None)

        if input is not None and self.stdin is not None:
            self.stdin.write(input)

        if timeout is not None:
            end_time = time.time() + timeout
        else:
            end_time = None

        data = None

        while self.poll() is None:
            if end_time is not None and time.time() >= end_time:
                raise TimeoutExpired(self.args, timeout, data)
            if self.stdin_pipe and data is None:
                data = self.stdout.read(4096)
            elif self.stdin_pipe:
                data += self.stdout.read(4096)
            else:
                # A pipe wasn't requested. Don't buffer the data.
                self.stdout.read(4096)

        return (data, None)

    def _receive_returncode(self):
        """ All output has been read of the stream, now we read
        the return code. """

        # Read until the returncode delimiter
        code = self.platform.channel.recvuntil(self.code_delim)
        code = code.split(self.code_delim)[0]
        code = code.strip().decode("utf-8")

        try:
            self.returncode = int(code)
        except ValueError:
            # This shouldn't happen, but if it does, there's nothing
            # we can do.
            self.returncode = 0


class Linux(pwncat.platform.Platform):
    """
    Concrete platform class abstracting interaction with a GNU/Linux remote
    host. See the base class (``pwncat.platform.Platform``) for more
    information on the implemented methods and interface definition.
    """

    def __init__(self, channel: pwncat.channel.Channel):
        super().__init__(channel)

    def get_host_hash(self) -> str:
        """
        Retrieve a string which uniquely identifies this victim host. On Unix-like
        platforms, this retrieves the hostname and MAC addresses of any available
        network interfaces and computes a hash, which should be unique regardless of
        connection method.

        :return: a unique string (normally a hash) identifying this host
        :rtype: str
        """

        try:
            result = self.run("hostname -f", shell=True, text=True, encoding="utf-8")
            hostname = result.stdout.strip()
        except CalledProcessError:
            hostname = self.channel.getpeername()[0]

        try:
            result = self.run("ifconfig -a", shell=True, text=True, encoding="utf-8")
            ifconfig = result.stdout.strip().lower()

            for line in ifconfig.split("\n"):
                if "hwaddr" in line and "00:00:00:00:00:00" not in line:
                    mac = line.split("hwaddr ")[1].split("\n")[0].strip()
                    break
            else:
                mac = None
        except CalledProcessError:
            # Attempt to use the `ip` command instead
            try:
                result = self.run(
                    "ip link show", shell=True, text=True, encoding="utf-8"
                )
                ip_out = result.stdout.strip().lower()
                for line in ip_out.split("\n"):
                    if "link/ether" in line and "00:00:00:00:00:00" not in line:
                        mac = line.split("link/ether ")[1].split(" ")[0]
                        break
                else:
                    mac = None
            except CalledProcessError:
                mac = None

        # In some (unlikely) cases, `mac` may be None, so we use `str` here.
        identifier = hostname + str(mac)
        return hashlib.md5(identifier.encode("utf-8")).hexdigest()

    def listdir(self, path=None) -> Generator[str, None, None]:
        """ List the contents of a directory. If ``path`` is None,
        then the contents of the current directory is listed. The
        list is not guaranteed to be sorted in any way.

        :param path: the directory to list
        :type path: str or Path-like
        :raise FileNotFoundError: When the requested directory is not a directory,
          does not exist, or you do not have execute permissions.
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
        text=None,
        env=None,
        **other_popen_kwargs,
    ) -> pwncat.subprocess.Popen:
        """
        Execute a process on the remote host with an interface similar to
        that of the python standard ``subprocess.Popen``. The returned
        object behaves much like a standard ``Popen`` object and conforms
        to the interface defined by ``pwncat.subprocess.Popen``. For
        an explanation of arguments, see ``pwncat.subprocess.Popen``.
        """

        if isinstance(args, list):
            command = shlex.join(args)
        elif isinstance(args, str):
            command = args
        else:
            raise ValueError("expected a command string or list of arguments")

        if shell:
            # Ensure this works normally
            command = shlex.join(["/bin/sh", "-c", command])

        if cwd is not None:
            command = f"(cd {cwd} && {command})"

        if env is not None:
            command = (
                " ".join(
                    [
                        f"{util.quote(name)}={util.quote(value)}"
                        for name, value in env.items()
                    ]
                )
                + " "
                + command
            )

        if isinstance(stdout, str):
            command += f" >{stdout}"
        elif stdout == pwncat.subprocess.DEVNULL:
            command += " >/dev/null"

        if isinstance(stderr, str):
            command += f" 2>{stderr}"
        elif stderr == pwncat.subprocess.DEVNULL:
            command += " 2>/dev/null"

        if isinstance(stdin, str):
            command += f" 0<{stdin}"
        elif stdin == pwncat.subprocess.DEVNULL:
            command += " 0</dev/null"
        else:
            # if a process requests stdin but we aren't expecting it
            # things can get wonky. We prevent that by kill stdin unless
            # explicitly asked for.
            command += " 0</dev/null"

        # Generate delimeters
        start_delim = util.random_string(10)
        end_delim = util.random_string(10)
        code_delim = util.random_string(10)

        commands = []
        commands.append(" export PS1=")
        commands.append("set +m")

        if stdin != pwncat.subprocess.PIPE:
            commands.append(
                f"{{ echo; echo {start_delim}; {command} && echo {end_delim} || echo {end_delim} & }} 2>/dev/null"
            )
        else:
            commands.append(f"echo; echo {start_delim}; {command}; echo {end_delim}")

        commands.append("set -m")

        # Build the final command
        command = ";".join(commands).encode("utf-8")

        if not text:
            self.stty("raw", echo=False)

        # Send the command
        self.channel.send(command + b"\n")

        return PopenLinux(
            self,
            args,
            stdout,
            stdin,
            text,
            encoding,
            start_delim,
            end_delim,
            code_delim,
        )

    def path(self, path: Optional[str] = None) -> pwncat.platform.Path:
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
        :rtype: pwncat.platform.Path
        """

    def chdir(self, path: Union[str, pwncat.platform.Path]):
        """
        Change directories to the given path. This method returns the current
        working directory prior to the change.

        :param path: a relative or absolute path to change to
        :type path: Union[str, pwncat.platform.Path]
        :return: current working directory prior to the change
        :raises:
          FileNotFoundError: the specified path doesn't exist
          NotADirectoryError: the specified path is not a directory
        """

    def open(self, path: Union[str, pwncat.platform.Path], mode: str):
        """
        Open a remote file for reading or writing. Normally, only one of read or
        write modes are allowed for a remote file, but this may change with
        future platforms. It is recommended to only use one mode when opening
        remote files. This method attempts to replicate the built-in ``open``
        function and returns a file-like object. The `b` mode is honored and
        if not present, a TextIOWrapper is used to wrap the file object to ensure
        text data is returned.

        :param path: path to the file
        :type path: Union[str, pwncat.platform.Path]
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
