#!/usr/bin/env python3
import re
from typing import Tuple, BinaryIO, Callable, List
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer, BaseRequestHandler
from prompt_toolkit.shortcuts import ProgressBar
from functools import partial
from colorama import Fore, Style
from io import TextIOWrapper
from enum import Enum, Flag, auto
import netifaces
import socket
import string
import random
import threading
import logging
import termios
import fcntl
import time
import tty
import sys
import os

CTRL_C = b"\x03"

ALPHANUMERIC = string.ascii_letters + string.digits


class State(Enum):
    """ The current PtyHandler state """

    NORMAL = auto()
    RAW = auto()
    COMMAND = auto()
    SINGLE = auto()


class Access(Flag):
    """ Check if you are able to read/write/execute a file """

    NONE = 0
    EXISTS = auto()
    READ = auto()
    WRITE = auto()
    EXECUTE = auto()
    SUID = auto()
    SGID = auto()
    REGULAR = auto()
    DIRECTORY = auto()
    # These identify if the parent directory exists and is
    # writable. This is useful to test whether we can create
    # the file if it doesn't exist
    PARENT_EXIST = auto()
    PARENT_WRITE = auto()


class Init(Enum):

    UNKNOWN = auto()
    SYSTEMD = auto()
    UPSTART = auto()
    SYSV = auto()


def isprintable(data) -> bool:
    """
    This is a convenience function to be used rather than the usual 
    ``str.printable`` boolean value, as that built-in **DOES NOT** consider
    newlines to be part of the printable data set (weird!)
    """

    if type(data) is str:
        data = data.encode("utf-8")
    for c in data:
        if c not in bytes(string.printable, "ascii"):
            return False

    return True


def human_readable_size(size, decimal_places=2):
    for unit in ["B", "KiB", "MiB", "GiB", "TiB"]:
        if size < 1024.0:
            break
        size /= 1024.0
    return f"{size:.{decimal_places}f}{unit}"


def human_readable_delta(seconds):
    """ This produces a human-readable time-delta output suitable for output to
    the terminal. It assumes that "seconds" is less than 1 day. I.e. it will only
    display at most, hours minutes and seconds. """

    if seconds < 60:
        return f"{seconds:.2f} seconds"

    output = []
    output.append(f"{int(seconds%60)} seconds")

    minutes = seconds // 60
    output.append(f"{minutes % 60} minutes")

    if minutes < 60:
        return f"{output[1]} and {output[0]}"

    hours = minutes // 60
    output.append(f"{hours} hours")

    return f"{output[2]}, {output[1]} and {output[0]}"


def join(argv: List[str]):
    """ Join the string much line shlex.join, except assume that each token
    is expecting double quotes. This allows variable references within the
    tokens. """

    return " ".join([quote(x) for x in argv])


def quote(token: str):
    """ Quote the token much like shlex.quote, except don't use single quotes
    this will escape any double quotes in the string and wrap it in double
    quotes. If there are no spaces, it returns the stirng unchanged. """
    for c in token:
        if c in string.whitespace:
            break
    else:
        return token

    return '"' + token.replace('"', '\\"') + '"'


ansi_escape_pattern = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def strip_ansi_escape(s: str) -> str:
    """
    Strip the ansi escape sequences out of the given string
    :param s: the string to strip
    :return: a version of 's' without ansi escape sequences
    """
    return ansi_escape_pattern.sub("", s)


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
            callback(len(chunk))
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
                callback(n)


def with_progress(title: str, target: Callable[[Callable], None], length: int = None):
    """ A shortcut to displaying a progress bar for various things. It will
    start a prompt_toolkit progress bar with the given title and a counter 
    with the given length. Then, it will call `target` with an `on_progress`
    parameter. This parameter should be called for all progress updates. See
    the `do_upload` and `do_download` for examples w/ copyfileobj """

    with ProgressBar(title) as pb:
        counter = pb(range(length))
        last_update = time.time()

        def on_progress(blocksz):
            """ Update the progress bar """
            if blocksz == -1:
                counter.stopped = True
                counter.done = True
                pb.invalidate()
                return

            counter.items_completed += blocksz
            if counter.items_completed >= counter.total:
                counter.done = True
                counter.stopped = True
            if (time.time() - last_update) > 0.1:
                pb.invalidate()

        target(on_progress)

        # https://github.com/prompt-toolkit/python-prompt-toolkit/issues/964
        time.sleep(0.1)


def random_string(length: int = 8):
    """ Create a random alphanumeric string """
    return "".join(random.choice(ALPHANUMERIC) for _ in range(length))


def enter_raw_mode():
    """ Set stdin/stdout to raw mode to pass data directly. 

        returns: the old state of the terminal
    """

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


def restore_terminal(state, new_line=True):
    """ restore the stdio state from the result of "enter_raw_mode" """
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, state[0])
    # tty.setcbreak(sys.stdin)
    fcntl.fcntl(sys.stdin, fcntl.F_SETFL, state[1])
    if new_line:
        sys.stdout.write("\n")


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


def erase_progress():
    """ Erase the last progress line. Useful for progress messages for long-running
    tasks, which don't need (or want) to be logged to the terminal """
    global LAST_LOG_MESSAGE

    sys.stdout.write(
        len(LAST_LOG_MESSAGE[0]) * "\b"
        + len(LAST_LOG_MESSAGE[0]) * " "
        + len(LAST_LOG_MESSAGE[0]) * "\b"
    )
    LAST_LOG_MESSAGE = (LAST_LOG_MESSAGE[0], False)


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

    if overlay or (LAST_LOG_MESSAGE[1] and (level == "success" or level == "error")):
        erase_progress()
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
