#!/usr/bin/env python3
from typing import Generator, Callable
from io import BufferedReader
import base64
import shlex

from pwncat.downloader.base import Downloader, DownloadError
from pwncat import util


class RawShellDownloader(Downloader):

    NAME = "raw"
    BINARIES = [("dd", "cat")]
    BLOCKSZ = 8192

    def command(self) -> Generator[str, None, None]:
        """ Yield list of commands to transfer the file """

        remote_path = shlex.quote(self.remote_path)
        blocksz = 1024 * 1024
        binary = self.pty.which("dd")

        if binary is None:
            binary = self.pty.which("cat")

        if "dd" in binary:
            pipe = self.pty.subprocess(f"dd if={remote_path} bs={blocksz} 2>/dev/null")
        else:
            pipe = self.pty.subprocess(f"cat {remote_path}")

        try:
            with open(self.local_path, "wb") as filp:
                util.copyfileobj(pipe, filp, self.on_progress)
        finally:
            self.on_progress(0, -1)
            pipe.close()

        return False

    def serve(self, on_progress: Callable):
        """ We don't need to start a server, but we do need to save the
            callback """
        self.on_progress = on_progress
