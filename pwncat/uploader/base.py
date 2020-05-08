#!/usr/bin/env python3
from typing import Generator, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, BaseRequestHandler
from functools import partial
import threading
import socket
import os

from pwncat import util


class UploadError(Exception):
    """ An error occurred while attempting to run a uploader """


class Uploader:

    # Binaries which are needed on the remote host for this uploader
    BINARIES = []

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Check if the given PTY connection can support this uploader """
        for binary in cls.BINARIES:
            if pty.which(binary) is None:
                raise UploadError(f"required remote binary not found: {binary}")

    def __init__(self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str):
        self.pty = pty
        self.local_path = local_path
        self.remote_path = remote_path

    def command(self) -> Generator[str, None, None]:
        """ Generate the commands needed to send this file. This is a 
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


class HttpGetFileHandler(BaseHTTPRequestHandler):
    def __init__(
        self, request, addr, server, uploader: "HTTPUploader", on_progress: Callable
    ):
        self.uploader = uploader
        self.on_progress = on_progress
        super(HttpGetFileHandler, self).__init__(request, addr, server)

    def do_GET(self):
        """ handle http POST request """

        if self.path != "/":
            self.send_error(404)
            return

        length = os.path.getsize(self.uploader.local_path)

        self.send_response(200)
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()

        with open(self.uploader.local_path, "rb") as filp:
            util.copyfileobj(filp, self.wfile, self.on_progress)

    def log_message(self, *args, **kwargs):
        return


class HTTPUploader(Uploader):
    """ Base class for HTTP POST based downloaders. This takes care of setting
        up the local HTTP server and saving the file. Just provide the commands
        for the remote host to trigger the upload """

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        super(HTTPUploader, cls).check(pty)
        """ Make sure we have an lhost """
        if pty.vars.get("lhost", None) is None:
            raise UploadError("no lhost provided")

    def __init__(
        self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str,
    ):
        super(HTTPUploader, self).__init__(pty, remote_path, local_path)
        self.server = None

    def serve(self, on_progress: Callable):
        self.server = HTTPServer(
            ("0.0.0.0", 0),
            partial(HttpGetFileHandler, uploader=self, on_progress=on_progress),
        )

        thread = threading.Thread(
            target=lambda: self.server.serve_forever(), daemon=True
        )
        thread.start()

    def shutdown(self):
        self.server.shutdown()


class RawUploader(Uploader):
    """ Base class for raw socket based downloaders. This takes care of setting
        up the socket server and saving the file. Just provide the commands to
        initiate the raw socket transfer on the remote host to trigger the 
        upload """

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        super(RawUploader, cls).check(pty)
        """ Make sure we have an lhost """
        if pty.vars.get("lhost", None) is None:
            raise UploadError("no lhost provided")

    def __init__(
        self, pty: "pwncat.pty.PtyHandler", remote_path: str, local_path: str,
    ):
        super(RawUploader, self).__init__(pty, remote_path, local_path)
        self.server = None

    def serve(self, on_progress: Callable):

        # Make sure it is accessible to the subclass
        local_path = self.local_path

        class SocketWrapper:
            def __init__(self, sock):
                self.s = sock

            def write(self, n: int):
                try:
                    return self.s.sendall(n)
                except socket.timeout:
                    return b""

        # Class to handle incoming connections
        class ReceiveFile(BaseRequestHandler):
            def handle(self):
                self.request.settimeout(1)
                with open(local_path, "rb") as filp:
                    util.copyfileobj(filp, SocketWrapper(self.request), on_progress)
                self.request.close()

        self.server = TCPServer(("0.0.0.0", 0), ReceiveFile)

        thread = threading.Thread(
            target=lambda: self.server.serve_forever(), daemon=True
        )
        thread.start()

    def shutdown(self):
        """ Shutdown the server """
        self.server.shutdown()
