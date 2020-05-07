#!/usr/bin/env python3
from typing import Generator, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, BaseRequestHandler
from functools import partial
import threading

from pwncat import util


class DownloadError(Exception):
    """ An error occurred while attempting to run a downloader """


class Downloader:

    # Binaries which are needed on the remote host for this downloader
    BINARIES = []

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Check if the given PTY connection can support this downloader """
        for binary in cls.BINARIES:
            if pty.which(binary) is None:
                raise DownloadError(f"required remote binary not found: {binary}")

    def __init__(self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str):
        self.pty = pty
        self.local_path = local_path
        self.remote_path = remote_path

    def command(self) -> Generator[str, None, None]:
        """ Generate the commands needed to send this file back. This is a 
            generator, which yields strings which will be executed on the remote
            host. """
        return

    def serve(self, on_progress: Callable):
        """ Start any servers on the local end which are needed to download the
            content. """
        return

    def shutdown(self):
        """ Shutdown any attacker servers that were started """
        return


class HttpPostFileReceiver(BaseHTTPRequestHandler):
    def __init__(self, request, addr, server, downloader: "HTTPDownloader"):
        self.downloader = downloader
        super(HttpPostFileReceiver, self).__init__(request, addr, server)

    def do_POST(self):
        """ handle http POST request """

        if self.path != "/":
            self.send_error(404)
            return

        self.send_response(200)
        self.end_headers()

        with open(self.downloader.local_path, "wb") as filp:
            util.copyfileobj(self.rfile, filp, self.downloader.progress)

    def log_message(self, *args, **kwargs):
        return


class HTTPDownloader(Downloader):
    """ Base class for HTTP POST based downloaders. This takes care of setting
        up the local HTTP server and saving the file. Just provide the commands
        for the remote host to trigger the upload """

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Make sure we have an lhost """
        if pty.vars.get("lhost", None) is None:
            raise DownloadError("no lhost provided")

    def __init__(
        self,
        pty: "pwncat.pty.PtyHandler",
        remote_path: str,
        local_path: str,
        on_progress: Callable = None,
    ):
        super(HTTPDownloader, self).__init__(pty, remote_path, local_path)
        self.server = None
        self.on_progress = on_progress

    def serve(self, on_progress: Callable):
        self.server = HTTPServer(
            ("0.0.0.0", 0), partial(HttpPostFileReceiver, downloader=self)
        )

        thread = threading.Thread(
            target=lambda: self.server.serve_forever(), daemon=True
        )
        thread.start()

    def shutdown(self):
        self.server.shutdown()


class RawDownloader(Downloader):
    """ Base class for raw socket based downloaders. This takes care of setting
        up the socket server and saving the file. Just provide the commands to
        initiate the raw socket transfer on the remote host to trigger the 
        upload """

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Make sure we have an lhost """
        if pty.vars.get("lhost", None) is None:
            raise DownloadError("no lhost provided")

    def __init__(
        self,
        pty: "pwncat.pty.PtyHandler",
        remote_path: str,
        local_path: str,
        on_progress: Callable = None,
    ):
        super(RawDownloader, self).__init__(pty, remote_path, local_path)
        self.server = None
        self.on_progress = on_progress

    def serve(self, on_progress: Callable):

        # Make sure it is accessible to the subclass
        local_path = self.local_path

        # Class to handle incoming connections
        class ReceiveFile(BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                with open(local_path, "wb") as fp:
                    util.copyfileobj(self.request.makefile("rb"), fp, on_progress)

        self.server = TCPServer(("0.0.0.0", 0), ReceiveFile)

        thread = threading.Thread(
            target=lambda: self.server.serve_forever(), daemon=True
        )
        thread.start()

    def shutdown(self):
        """ Shutdown the server """
        self.server.shutdown()
