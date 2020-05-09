#!/usr/bin/env python3
from typing import Tuple, BinaryIO, Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, BaseRequestHandler
from functools import partial
from colorama import Fore, Style
from io import TextIOWrapper
import netifaces
import socket
import threading
import logging
import termios
import fcntl
import tty
import sys
import os

CTRL_C = b"\x03"


def copyfileobj(src, dst, callback, nomv=False):
    """ Copy a file object to another file object with a callback.
        This method assumes that both files are binary and support readinto
    """

    try:
        length = os.stat(src.fileno()).st_size
        length = min(length, 1024 * 1024)
    except (OSError, AttributeError):
        length = 1024 * 1024

    copied = 0

    if getattr(src, "readinto", None) is None or nomv:
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

    info("setting terminal to raw mode and disabling echo", overlay=True)
    success("pwncat is ready 🐈\n", overlay=True)

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
    # tty.setcbreak(sys.stdin)
    fcntl.fcntl(sys.stdin, fcntl.F_SETFL, state[1])
    sys.stdout.write("\n")
    info("local terminal restored")


def get_ip_addr() -> str:
    """ Retrieve the current IP address. This will return the first tun/tap
    interface if availabe. Otherwise, it will return the first "normal" 
    interface with no preference for wired/wireless. """

    PROTO = netifaces.AF_INET
    ifaces = [
        iface
        for iface in netifaces.interfaces()
        if not iface.startswith("virbr")
        and not iface.startswith("lo")
        and not iface.startswith("docker")
    ]
    targets = []

    # look for a tun/tap interface
    for iface in ifaces:
        if iface.startswith("tun") or iface.startswith("tap"):
            addrs = netifaces.ifaddresses(iface)
            if PROTO not in addrs:
                continue
            for a in addrs[PROTO]:
                if "addr" in a:
                    return a["addr"]

    # Try again. We don't care what kind now
    for iface in ifaces:
        addrs = netifaces.ifaddresses(iface)
        if PROTO not in addrs:
            continue
        for a in addrs[PROTO]:
            if "addr" in a:
                return a["addr"]

    return None


LAST_LOG_MESSAGE = ("", False)
PROG_ANIMATION = "/-\\"
LAST_PROG_ANIM = -1


def log(level, message, overlay=False):
    global LAST_LOG_MESSAGE
    global LAST_PROG_ANIM

    prefix = {
        "info": f"[{Fore.BLUE}+{Fore.RESET}]",
        "success": f"[{Fore.GREEN}+{Fore.RESET}]",
        "warn": f"[{Fore.YELLOW}?{Fore.RESET}]",
        "error": f"[{Fore.RED}!{Fore.RESET}]",
        "prog": f"[{Fore.CYAN}+{Fore.RESET}]",
    }

    if overlay:
        sys.stdout.write(f"\r{len(LAST_LOG_MESSAGE[0])*' '}\r")
    elif LAST_LOG_MESSAGE[1]:
        sys.stdout.write("\n")

    if level == "prog":
        LAST_PROG_ANIM = (LAST_PROG_ANIM + 1) % len(PROG_ANIMATION)
        prefix["prog"] = prefix["prog"].replace("+", PROG_ANIMATION[LAST_PROG_ANIM])

    LAST_LOG_MESSAGE = (
        f"{prefix[level]} {Style.DIM}{message}{Style.RESET_ALL}",
        overlay,
    )
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


def success(message, overlay=False):
    log("success", message, overlay)


def progress(message, overlay=True):
    log("prog", message, overlay)
