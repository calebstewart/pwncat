#!/usr/bin/env python3
from typing import Callable
import os

from pwncat.gtfobins import Capability, Stream
from pwncat.downloader.base import Downloader, DownloadError
from pwncat import util


class GtfoBinsDownloader(Downloader):

    NAME = "gtfobins"

    def __init__(self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str):
        super(GtfoBinsDownloader, self).__init__(pty, remote_path, local_path)
        self.on_progress = None

    def command(self):

        with self.pty.open(self.remote_path, "rb") as remote:
            with open(self.local_path, "wb") as local:
                util.copyfileobj(remote, local, self.on_progress)

    def serve(self, on_progress: Callable):
        self.on_progress = on_progress
