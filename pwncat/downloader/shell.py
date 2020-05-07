#!/usr/bin/env python3
from typing import Generator, Callable
import base64
import shlex

from pwncat.downloader.base import Downloader, DownloadError


class ShellDownloader(Downloader):

    NAME = "shell"
    BINARIES = ["dd", "base64"]
    BLOCKSZ = 8192

    def command(self) -> Generator[str, None, None]:
        """ Yield list of commands to transfer the file """

        remote_path = shlex.quote(self.remote_path)

        with open(self.local_path, "wb") as filp:
            blocknr = 0
            copied = 0
            while True:

                # Read the data
                x = yield "dd if={} bs={} skip={} count=1 2>/dev/null | base64 -w0".format(
                    remote_path, self.BLOCKSZ, blocknr
                )
                if x == b"" or x == b"\r\n":
                    break

                # Decode the data
                data = base64.b64decode(x)

                # Send the data and call the progress function
                filp.write(data)
                copied += data
                self.on_progress(copied, len(data))

                # Increment block number
                blocknr += 1

    def serve(self, on_progress: Callable):
        """ We don't need to start a server, but we do need to save the
            callback """
        self.on_progress = on_progress
