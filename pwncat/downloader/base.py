#!/usr/bin/env python3
from typing import Generator, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, BaseRequestHandler
from functools import partial
import threading
import socket
import os

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
            if isinstance(binary, list) or isinstance(binary, tuple):
                for equivalent in binary:
                    if pty.which(equivalent):
                        return
            elif pty.which(binary) is not None:
                return
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
    def __init__(
        self, request, addr, server, downloader: "HTTPDownloader", on_progress: Callable
    ):
        self.downloader = downloader
        self.on_progress = on_progress
        super(HttpPostFileReceiver, self).__init__(request, addr, server)

    def do_PUT(self):
        """ handle http POST request """

        if self.path != f"/{os.path.basename(self.downloader.remote_path)}":
            self.send_error(404)
            return

        length = int(self.headers["Content-Length"])
        copied = 0
        chunksz = 1024 * 1024

        self.send_response(200)
        self.send_header("Content-Length", "1")
        self.end_headers()
        self.flush_headers()

        self.rfile = self.rfile.detach()

        with open(self.downloader.local_path, "wb") as filp:
            while copied < length:
                block = self.rfile.read(chunksz)
                filp.write(block)
                copied += len(block)
                self.on_progress(copied, len(block))

    def do_POST(self):
        return self.do_PUT()

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
        self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str,
    ):
        super(HTTPDownloader, self).__init__(pty, remote_path, local_path)
        self.server = None

    def serve(self, on_progress: Callable):
        self.server = HTTPServer(
            ("0.0.0.0", 0),
            partial(HttpPostFileReceiver, downloader=self, on_progress=on_progress),
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
        self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str,
    ):
        super(RawDownloader, self).__init__(pty, remote_path, local_path)
        self.server = None

    def serve(self, on_progress: Callable):

        # Make sure it is accessible to the subclass
        local_path = self.local_path

        class SocketWrapper:
            def __init__(self, sock):
                self.s = sock

            def read(self, n: int):
                try:
                    return self.s.recv(n)
                except socket.timeout:
                    return b""

        # Class to handle incoming connections
        class ReceiveFile(BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                with open(local_path, "wb") as fp:
                    util.copyfileobj(SocketWrapper(self.request), fp, on_progress)
                self.request.close()

        self.server = TCPServer(("0.0.0.0", 0), ReceiveFile)

        thread = threading.Thread(
            target=lambda: self.server.serve_forever(), daemon=True
        )
        thread.start()

    def shutdown(self):
        """ Shutdown the server """
        self.server.shutdown()
