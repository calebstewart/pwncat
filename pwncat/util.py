#!/usr/bin/env python3
from typing import Tuple, BinaryIO, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, BaseRequestHandler
from functools import partial
from colorama import Fore
from io import TextIOWrapper
import socket
import threading
import logging
import termios
import fcntl
import tty
import sys
import os


class SingleFileServer(BaseHTTPRequestHandler):
    def __init__(
        self,
        request,
        addr,
        server,
        name: str,
        path: str,
        content_type="application/octet-stream",
        progress=None,
    ):
        self.file_name = name
        self.file_path = path
        self.content_type = content_type
        self.progress = progress

        super(SingleFileServer, self).__init__(request, addr, server)

    def do_GET(self):
        """ Handle GET requests """

        # We only serve this one file
        if self.path != f"/{self.file_name}":
            self.send_error(404)
            return

        length = os.path.getsize(self.file_path)

        # Send response headers
        self.send_response(200)
        self.send_header("Content-Type", self.content_type)
        self.send_header("Content-Length", str(length))
        self.end_headers()

        # Send data
        with open(self.file_path, "rb") as fp:
            copyfileobj(fp, self.wfile, self.progress)

    def log_message(self, fmt, *args):
        """ BE QUIET """
        return


class SingleFileReceiver(BaseHTTPRequestHandler):
    def __init__(self, request, addr, server, name, dest_path, progress):
        self.dest_path = dest_path
        self.file_name = name
        self.progress = progress
        super(SingleFileReceiver, self).__init__(request, addr, server)

    def do_POST(self):
        """ handle http POST request """

        if self.path != f"/{self.file_name}":
            self.send_error(404)
            return

        self.send_response(200)
        self.end_headers()

        with open(self.dest_path, "wb") as fp:
            copyfileobj(self.rfile, fp, self.progress)

    def log_message(self, *args, **kwargs):
        return


def copyfileobj(src, dst, callback):
    """ Copy a file object to another file object with a callback.
        This method assumes that both files are binary and support readinto
    """

    try:
        length = os.stat(src.fileno()).st_size
        length = min(length, 1024 * 1024)
    except (OSError, AttributeError):
        length = 1024 * 1024

    copied = 0

    if getattr(src, "readinto", None) is None:
        for chunk in iter(lambda: src.read(length), b""):
            dst.write(chunk)
            copied += len(chunk)
            callback(copied, len(chunk))
    else:
        with memoryview(bytearray(length)) as mv:
            while True:
                n = src.readinto(mv)
                if not n:
                    break
                if n < length:
                    with mv[:n] as smv:
                        dst.write(smv)
                else:
                    dst.write(mv)
                copied += n
                callback(copied, n)


def enter_raw_mode():
    """ Set stdin/stdout to raw mode to pass data directly. 

        returns: the old state of the terminal
    """

    info("setting terminal to raw mode and disabling echo")

    # Ensure we don't have any weird buffering issues
    sys.stdout.flush()

    # Python doesn't provide a way to use setvbuf, so we reopen stdout
    # and specify no buffering. Duplicating stdin allows the user to press C-d
    # at the local prompt, and still be able to return to the remote prompt.
    try:
        os.dup2(sys.stdin.fileno(), sys.stdout.fileno())
    except OSError:
        pass
    sys.stdout = TextIOWrapper(
        os.fdopen(os.dup(sys.stdin.fileno()), "bw", buffering=0),
        write_through=True,
        line_buffering=False,
    )

    # Grab and duplicate current attributes
    fild = sys.stdin.fileno()
    old = termios.tcgetattr(fild)
    new = termios.tcgetattr(fild)

    # Remove ECHO from lflag and ensure we won't block
    new[3] &= ~(termios.ECHO | termios.ICANON)
    new[6][termios.VMIN] = 0
    new[6][termios.VTIME] = 0
    termios.tcsetattr(fild, termios.TCSADRAIN, new)

    # Set raw mode
    tty.setraw(sys.stdin)

    orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
    fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl | os.O_NONBLOCK)

    return old, orig_fl


def restore_terminal(state):
    """ restore the stdio state from the result of "enter_raw_mode" """
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, state[0])
    tty.setcbreak(sys.stdin)
    fcntl.fcntl(sys.stdin, fcntl.F_SETFL, state[1])
    sys.stdout.write("\n")
    info("local terminal restored")


def serve_http_file(
    path: str, name: str, port: int = 0, progress: Callable = None
) -> HTTPServer:
    """ Serve a single file on the given port over HTTP. """

    # Create an HTTP server
    server = HTTPServer(
        ("0.0.0.0", port),
        partial(SingleFileServer, name=name, path=path, progress=progress),
    )

    # Start serving the file
    thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    thread.start()

    return server


def receive_http_file(
    dest_path: str, name: str, port: int = 0, progress: Callable = None
) -> HTTPServer:
    """ Serve a single file on the given port over HTTP. """

    # Create an HTTP server
    server = HTTPServer(
        ("0.0.0.0", port),
        partial(SingleFileReceiver, name=name, dest_path=dest_path, progress=progress),
    )

    # Start serving the file
    thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    thread.start()

    return server


def receive_raw_file(
    dest_path: str, name: str, port: int = 0, progress: Callable = None
) -> TCPServer:
    """ Serve a file on the given port """

    class SocketWrapper:
        def __init__(self, sock):
            self.s = sock

        def read(self, n: int):
            try:
                return self.s.recv(n)
            except socket.timeout:
                return b""

    class ReceiveFile(BaseRequestHandler):
        def handle(self):
            # We shouldn't block that long during a streaming transfer
            self.request.settimeout(1)
            with open(dest_path, "wb") as fp:
                copyfileobj(SocketWrapper(self.request), fp, progress)

    server = TCPServer(("0.0.0.0", port), ReceiveFile)
    thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    thread.start()

    return server


def serve_raw_file(
    path: str, name: str, port: int = 0, progress: Callable = None
) -> TCPServer:
    """ Serve a file on the given port """

    class SocketWrapper:
        def __init__(self, sock):
            self.s = sock

        def write(self, n: int):
            return self.s.send(n)

    class SendFile(BaseRequestHandler):
        def handle(self):
            with open(path, "rb") as fp:
                copyfileobj(fp, SocketWrapper(self.request), progress)
            self.request.close()

    server = TCPServer(("0.0.0.0", port), SendFile)
    thread = threading.Thread(target=lambda: server.serve_forever(), daemon=True)
    thread.start()

    return server


LAST_LOG_MESSAGE = ("", False)
PROG_ANIMATION = ["/-\\"]
LAST_PROG_ANIM = -1


def log(level, message, overlay=False):
    global LAST_LOG_MESSAGE
    global LAST_PROG_ANIM

    prefix = {
        "info": f"[{Fore.BLUE}+{Fore.RESET}] ",
        "warn": f"[{Fore.YELLOW}?{Fore.RESET}] ",
        "error": f"[{Fore.RED}!{Fore.RESET}] ",
        "prog": f"[{Fore.CYAN}+{Fore.RESET}] ",
    }

    if overlay:
        sys.stdout.write(f"\r{len(LAST_LOG_MESSAGE[0])*' '}\r")
    elif LAST_LOG_MESSAGE[1]:
        sys.stdout.write("\n")

    if level == "prog":
        LAST_PROG_ANIM = (LAST_PROG_ANIM + 1) % len(PROG_ANIMATION)
        prefix["prog"] = prefix["prog"].replace("+", PROG_ANIMATION[LAST_PROG_ANIM])

    LAST_LOG_MESSAGE = (f"{prefix[level]} {message}", overlay)
    sys.stdout.write(LAST_LOG_MESSAGE[0])

    if not overlay:
        sys.stdout.write("\n")
    else:
        sys.stdout.flush()


def info(message, overlay=False):
    log("info", message, overlay)


def warn(message, overlay=False):
    log("warn", message, overlay)


def error(message, overlay=False):
    log("error", message, overlay)


# def progress(message, overlay=False):
#    log("prog", message, overlay)
