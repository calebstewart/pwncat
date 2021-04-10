#!/usr/bin/env python3
import io

import pytest
import paramiko


def test_digitalocean(digital_ocean):

    key = paramiko.rsakey.RSAKey.from_private_key(
        io.StringIO(digital_ocean.ssh_key.exportKey("PEM").decode("utf-8"))
    )

    ubuntu = digital_ocean.ubuntu
    ubuntu.load()

    client = paramiko.client.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)
    client.connect(ubuntu.ip_address, username=digital_ocean.user, pkey=key)

    stdin, stdout, stderr = client.exec_command("whoami")

    assert stdout.read().strip().decode("utf-8") == "root"
