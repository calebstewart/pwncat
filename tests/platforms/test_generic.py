#!/usr/bin/env python3
import os
import base64
import subprocess

import pytest
from pwncat.util import random_string


def test_platform_file_io(session):
    """ Test file read/write of printable data """

    # Generate random binary data
    contents = os.urandom(1024)

    # Create a new temporary file
    with session.platform.tempfile(mode="wb") as filp:
        filp.write(contents)
        path = filp.name

    # Ensure it exists
    assert session.platform.Path(path).exists()

    # Read the data back and ensure it matches
    with session.platform.open(path, "rb") as filp:
        assert contents == filp.read()


def test_platform_dir_io(session):
    """ Test creating a directory and interacting with the contents """

    # Create a path object representing the new remote directory
    path = session.platform.Path(random_string())

    # Create the directory
    path.mkdir()

    # We construct a new path object to avoid cached stat results
    assert session.platform.Path(str(path)).is_dir()

    # Create a file
    (path / "test.txt").touch()

    assert "test.txt" in [item.name for item in path.iterdir()]


def test_platform_run(session):

    # Ensure command output works
    output_remote = session.platform.run(
        ["echo", "hello world"], shell=True, capture_output=True, text=True, check=True
    )
    assert output_remote.stdout == "hello world\n"

    # Ensure we capture the process return code properly
    with pytest.raises(subprocess.CalledProcessError):
        session.platform.run("this_command_doesnt_exist", shell=True, check=True)


def test_platform_su(session):
    """ Test running `su` """

    try:
        session.platform.su("john", "P@ssw0rd")
        session.platform.refresh_uid()

        assert session.current_user().name == "john"

        with pytest.raises(PermissionError):
            session.platform.su("caleb", "wrongpassword")

    except NotImplementedError:
        pass


def test_platform_sudo(session):
    """ Testing running `sudo` """

    try:

        # We have permission to run `/bin/sh *`, so this should succeed
        proc = session.platform.sudo(
            "whoami", user="john", shell=True, stdout=subprocess.PIPE, text=True
        )
        output = proc.stdout.read().strip()

        assert proc.wait() == 0
        assert output == "john"

        # We don't have permission to run a bare `whoami`, so this should fail
        proc = session.platform.sudo(
            ["whoami"], user="john", shell=False, stdout=subprocess.PIPE, text=True
        )
        output = proc.stdout.read().strip()

        assert proc.wait() != 0
        assert output != "john"
    except NotImplementedError:
        pass
