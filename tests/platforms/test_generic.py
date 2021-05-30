#!/usr/bin/env python3
import os
import base64
import subprocess

import pytest
from pwncat.util import random_string


def test_file_read_write(session):
    """ Test file read/write of printable data """

    contents = os.urandom(1024)
    with session.platform.tempfile(mode="wb") as filp:
        filp.write(contents)
        path = filp.name

    assert session.platform.Path(path).exists()

    with session.platform.open(path, "rb") as filp:
        assert contents == filp.read()


def test_platform_mkdir(session):
    """ Test creating a directory """

    path = session.platform.Path(random_string())

    path.mkdir()
    assert session.platform.Path(str(path)).is_dir()


def test_platform_run(session):

    # Ensure command output works
    output_remote = session.platform.run(
        ["echo", "hello world"], capture_output=True, text=True, check=True
    )
    assert output_remote.stdout == "hello world\n"

    # Ensure we capture the process return code properly
    with pytest.raises(subprocess.CalledProcessError):
        session.platform.run("this_command_doesnt_exist", shell=True, check=True)
