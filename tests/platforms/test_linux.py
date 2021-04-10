#!/usr/bin/env python3
import subprocess

import pytest


def test_linux_popen(session):

    # Ensure command output works
    id_output_local = subprocess.run(["id"], capture_output=True, text=True)
    id_output_remote = session.platform.run(["id"], capture_output=True, text=True)
    assert id_output_local.stdout == id_output_remote.stdout

    # Ensure we capture the process return code properly
    with pytest.raises(subprocess.CalledProcessError):
        session.platform.run("echo something | grep nothing", shell=True, check=True)
