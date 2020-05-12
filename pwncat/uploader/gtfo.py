#!/usr/bin/env python3
from typing import Callable
import os

from pwncat.uploader.base import Uploader, UploadError
from pwncat import util


def fake(x, y):
    pass


class GtfoBinsUploader(Uploader):

    NAME = "gtfobins"

    def __init__(self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str):
        super(GtfoBinsUploader, self).__init__(pty, remote_path, local_path)

        self.length = os.path.getsize(local_path)
        self.on_progress = None

    def command(self):
        with self.pty.open(self.remote_path, "wb", length=self.length) as remote:
            with open(self.local_path, "rb") as local:
                util.copyfileobj(local, remote, self.on_progress)

    def serve(self, on_progress: Callable):
        self.on_progress = on_progress
