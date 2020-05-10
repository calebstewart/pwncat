#!/usr/bin/env python3
from typing import Generator, Callable
from io import BufferedReader
import base64
import shlex
import socket
import os

from pwncat.uploader.base import Uploader, UploadError
from pwncat import util


class RawShellUploader(Uploader):

    NAME = "raw"
    BINARIES = ["dd"]
    BLOCKSZ = 8192

    def command(self) -> Generator[str, None, None]:
        """ Yield list of commands to transfer the file """

        remote_path = shlex.quote(self.remote_path)
        file_sz = os.path.getsize(self.local_path) - 1

        # Put the remote terminal in raw mode
        self.pty.raw()

        self.pty.process(
            f"dd of={remote_path} bs=1 count={file_sz} 2>/dev/null", delim=False
        )

        pty = self.pty

        class SocketWrapper:
            def write(self, data):
                try:
                    n = pty.client.send(data)
                except socket.error:
                    return 0
                return n

        try:
            with open(self.local_path, "rb") as filp:
                util.copyfileobj(filp, SocketWrapper(), self.on_progress)
        finally:
            self.on_progress(0, -1)

        # Get back to a terminal
        self.pty.client.send(util.CTRL_C)
        self.pty.reset()

        return False

    def serve(self, on_progress: Callable):
        """ We don't need to start a server, but we do need to save the
            callback """
        self.on_progress = on_progress
