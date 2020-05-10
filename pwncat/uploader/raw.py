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
        file_sz = os.path.getsize(self.local_path)
        dd = self.pty.which("dd")

        with self.pty.subprocess(
            f"{dd} of={remote_path} bs=1 count={file_sz} 2>/dev/null", mode="wb"
        ) as stream:
            try:
                with open(self.local_path, "rb") as filp:
                    util.copyfileobj(filp, stream, self.on_progress)
            finally:
                self.on_progress(0, -1)

        # Get back to a terminal

        return False

    def serve(self, on_progress: Callable):
        """ We don't need to start a server, but we do need to save the
            callback """
        self.on_progress = on_progress
