#!/usr/bin/env python3
from typing import Generator, Callable
import base64
import shlex

from pwncat.uploader.base import Uploader, UploadError


class ShellUploader(Uploader):

    NAME = "shell"
    BINARIES = ["base64"]
    BLOCKSZ = 8192

    def command(self) -> Generator[str, None, None]:
        """ Yield list of commands to transfer the file """

        remote_path = shlex.quote(self.remote_path)

        # Empty the file
        self.pty.run(f"echo -n > {remote_path}")

        with open(self.local_path, "rb") as filp:
            copied = 0
            for block in iter(lambda: filp.read(self.BLOCKSZ), b""):

                # Encode as a base64 string
                encoded = base64.b64encode(block).decode("utf-8")

                # Read the data
                self.pty.run(f"echo -n {encoded} | base64 -d >> {remote_path}")

                copied += len(block)
                self.on_progress(copied, len(block))

    def serve(self, on_progress: Callable):
        """ We don't need to start a server, but we do need to save the
            callback """
        self.on_progress = on_progress
