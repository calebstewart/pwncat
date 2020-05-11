#!/usr/bin/env python3
from io import RawIOBase
import socket


class RemoteBinaryPipe(RawIOBase):
    """ Encapsulate a piped interaction with a remote process. The remote PTY
    should have been placed in raw mode prior to this object being created, and 
    the appropriate flags in pty already modified. If EOF is found or the object
    is closed, it will restore the state of the terminal (w/ `reset`). No further
    reading or writing will be allowed. """

    def __init__(
        self, pty: "pwncat.pty.PtyHandler", mode: str, delim: bytes, binary: bool
    ):
        self.pty = pty
        self.delim = delim
        self.eof = 0
        self.next_eof = False
        self.binary = binary
        self.split_eof = b""
        self.mode = mode

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return "w" in self.mode

    def on_eof(self):
        if self.eof:
            return

        # Set eof flag
        self.eof = 1

        # Reset the terminal
        self.pty.restore_remote()
        # Send a bare echo, and read all data to ensure we don't clobber the
        # output of the user's terminal
        self.pty.run("echo")

    def close(self):
        if self.eof:
            return

        # Kill the last job. This should be us. We can only run as a job when we
        # don't request write support, because stdin is taken away from the
        # subprocess. This is dangerous, because we have no way to kill the new
        # process if it misbehaves. Use "w" carefully with known good
        # parameters.
        if "w" not in self.mode:
            self.pty.run("kill -9 %%", wait=False)

        # Cleanup
        self.on_eof()

    def readinto(self, b: bytearray):
        if self.eof:
            return None

        if isinstance(b, memoryview):
            obj = b.obj
        else:
            obj = b

        # Receive the data
        while True:
            try:
                n = self.pty.client.recv_into(b)
                break
            except (BlockingIOError, socket.error):
                pass

        obj = bytes(b)

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
                if bytes(b[-i:]) == piece:
                    try:
                        # Peak the next bytes, to see if this is actually the
                        # delimeter
                        rest = self.pty.client.recv(
                            len(self.delim) - len(piece),
                            socket.MSG_PEEK | socket.MSG_DONTWAIT,
                        )
                    except (socket.error, BlockingIOError):
                        rest = b""
                    # It is!
                    if (piece + rest) == self.delim:
                        # Receive the delimeter
                        self.pty.client.recv(len(self.delim) - len(piece))
                        # Adjust result
                        n -= len(piece)
                        # Set EOF for next read
                        self.on_eof()

        return n

    def flush_read(self):
        """ read all until eof and ignore it """
        for block in iter(lambda: self.read(1024 * 1024), b""):
            pass

    def write(self, data: bytes):
        if self.eof:
            raise EOFError
        return self.pty.client.send(data)
