#!/usr/bin/env python3
import socket
import time
from io import RawIOBase
from typing import Union

import pwncat


class RemoteBinaryPipe(RawIOBase):
    """ Encapsulate a piped interaction with a remote process. The remote PTY
    should have been placed in raw mode prior to this object being created, and 
    the appropriate flags in pty already modified. If EOF is found or the object
    is closed, it will restore the state of the terminal (w/ `reset`). No further
    reading or writing will be allowed. """

    def __init__(
        self,
        mode: str,
        delim: bytes,
        binary: bool,
        exit_cmd: Union[bytes, str],
        length: int = None,
    ):
        if isinstance(exit_cmd, str):
            exit_cmd = exit_cmd.encode("utf-8")

        self.delim = delim
        self.eof = 0
        self.next_eof = False
        self.binary = binary
        self.split_eof = b""
        self.mode = mode
        self.exit_cmd: bytes = exit_cmd
        self.count = 0
        self.name = None
        self.length = length

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return "w" in self.mode

    def on_eof(self):
        if self.eof:
            return

        # Set eof flag
        self.eof = 1

        # Send exit command if it was provided
        if self.exit_cmd and len(self.exit_cmd):
            pwncat.victim.client.send(self.exit_cmd)

        # Flush anything in the queue
        pwncat.victim.flush_output()

        # Reset the terminal
        pwncat.victim.restore_remote()
        # pwncat.victim.reset()
        # Send a bare echo, and read all data to ensure we don't clobber the
        # output of the user's terminal

    def close(self):

        if self.eof:
            return

        if "w" in self.mode and self.length is not None and self.count < self.length:
            # We **have** to finish writing or the shell won't come back in
            # most cases. This block only normally executes when an exception
            # auto-closes a file object.
            self.write((self.length - self.count) * b"\x00")

        # Kill the last job. This should be us. We can only run as a job when we
        # don't request write support, because stdin is taken away from the
        # subprocess. This is dangerous, because we have no way to kill the new
        # process if it misbehaves. Use "w" carefully with known good
        # parameters.
        if "w" not in self.mode:
            pwncat.victim.run("kill -9 %%", wait=False)

        # Cleanup
        self.on_eof()

    def readinto(self, b: bytearray):
        if self.eof:
            return None

        obj = b.obj if isinstance(b, memoryview) else b
        # Receive the data
        if getattr(pwncat.victim.client, "recv_into", None) is not None:
            while True:
                try:
                    n = pwncat.victim.client.recv_into(b)
                    break
                except (BlockingIOError, socket.error):
                    pass
        else:
            data = pwncat.victim.client.recv(len(b))
            b[: len(data)] = data
            n = len(data)

        # obj = bytes(b)
        obj = bytes(b[:n])

        # Check for EOF
        if self.delim in obj:

            self.on_eof()
            n = obj.find(self.delim)
            return n
        else:
            # Check for EOF split across blocks
            for i in range(1, len(self.delim)):
                # See if a piece of the delimeter is at the end of this block
                piece = self.delim[:i]
                # if bytes(b[-i:]) == piece:
                if obj[-i:] == piece:
                    try:
                        # Peak the next bytes, to see if this is actually the
                        # delimeter
                        rest = pwncat.victim.client.recv(
                            len(self.delim) - len(piece),
                            # socket.MSG_PEEK | socket.MSG_DONTWAIT,
                            socket.MSG_PEEK,
                        )
                    except (socket.error, BlockingIOError):
                        rest = b""
                    # rest = pwncat.victim.peek_output(some=True)
                    # It is!
                    if (piece + rest) == self.delim:
                        # Receive the delimeter
                        pwncat.victim.client.recv(len(self.delim) - len(piece))
                        # Adjust result
                        n -= len(piece)
                        # Set EOF for next read

                        self.on_eof()

        return n

    def flush_read(self):
        """ read all until eof and ignore it """
        for _ in iter(lambda: self.read(1024 * 1024), b""):
            pass

    def write(self, data: bytes):

        if self.eof:
            return None

        if self.length is not None:
            if (len(data) + self.count) > self.length:
                data = data[: (self.length - self.count)]

        try:
            n = pwncat.victim.client.send(data)
        except (socket.timeout, BlockingIOError):
            n = 0
        if n == 0:
            return None

        self.count += n
        if self.length is not None and self.count >= self.length:
            self.on_eof()

        return n
