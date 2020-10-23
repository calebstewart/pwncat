#!/usr/bin/env python3
import os
import socket
import subprocess
import multiprocessing

import pytest

import pwncat.platform
import pwncat.subprocess


def start_bind_shell(addr, port):
    """ Start a reverse shell in a subprocess """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s = socket.create_server((addr, port))

    while True:
        c, _ = s.accept()
        os.dup2(c.fileno(), 0)
        os.dup2(c.fileno(), 1)
        os.dup2(c.fileno(), 2)
        p = subprocess.call(["/bin/sh", "-i"])


def setup_module(module):
    module.popen = multiprocessing.Process(
        target=start_bind_shell, args=("127.0.0.1", 4444)
    )


def teardown_module(module):
    module.popen.kill()
    module.popen.join()


@pytest.fixture
def target():

    return pwncat.platform.create("linux", host="127.0.0.1", port=4444)


class TestLinux:
    def test_pty(self, target):
        """ Test that getting a pty works """

        target.get_pty()

        assert target.has_pty

    # def test_command_output(self):
    #     """ Test that we can run a command and retrieve output """

    #     p = self.target.Popen(
    #         ["hostname", "-f"], stdout=pwncat.subprocess.PIPE, text=True
    #     )
    #     stdout, _ = p.communicate()

    #     assert stdout is not None
    #     assert stdout != ""
    #     assert p.returncode == 0

    # def test_shell_command(self):
    #     """ Test that we can run a command with shell syntax """

    #     p = self.target.Popen(
    #         "cat /etc/*-release | grep 'Doesnt Exist'",
    #         shell=True,
    #         stdout=pwncat.subprocess.PIPE,
    #         text=True,
    #     )
    #     stdout, _ = p.communicate()

    #     # Grep should have returned non-zero
    #     assert p.returncode != 0

    # def test_file_io(self):
    #     """ Test that we can read/write files on the target """

    #     # Generate random data
    #     data = os.urandom(8192)

    #     # Write data to a file
    #     with self.target.open("/tmp/pwncat-test", "w") as filp:
    #         filp.write(data)

    #     # Read data back and ensure it's the same
    #     with self.target.open("/tmp/pwncat-test", "r") as filp:
    #         assert filp.read() == data
