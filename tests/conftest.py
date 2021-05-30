#!/usr/bin/env python3
import os
import time
import random
import socket
import string
import dataclasses
from io import StringIO

import pytest
from pwncat.channel import ChannelError
from Crypto.PublicKey import RSA

PLATFORM_MAP = {"ubuntu": "linux", "centos": "linux", "windows": "windows"}


def connection_details_for(name):
    """Get connection details from environment for the given
    host type name (e.g. ubuntu, centos, windows)"""

    if name not in PLATFORM_MAP:
        pytest.skip(f"{name} is not a known target")

    if (
        f"{name.upper()}_HOST" not in os.environ
        or f"{name.upper()}_BIND_PORT" not in os.environ
    ):
        pytest.skip(f"{name} not available")

    return {
        "platform": PLATFORM_MAP[name],
        "host": os.environ[f"{name.upper()}_HOST"],
        "port": int(os.environ[f"{name.upper()}_BIND_PORT"]),
        "protocol": "connect",
    }


@pytest.fixture(params=["ubuntu", "centos"])
def linux_details(request):
    """ Get available connection details for linux hosts """
    return connection_details_for(request.param)


@pytest.fixture(params=["windows"])
def windows_details(request):
    """ Get available connection details for windows hosts """
    return connection_details_for(request.param)


def session_for(request):

    # Grab details for this target
    details = connection_details_for(request.param)

    # Check if there are manager arguments
    manager_args = getattr(
        request.node.get_closest_marker("manager_config"), "args", {}
    )
    if not manager_args:
        manager_args = {}

    if "config" not in manager_args:
        manager_args["config"] = StringIO(
            """
set -g db "memory://"
        """
        )

    import pwncat.manager

    with pwncat.manager.Manager(**manager_args) as manager:
        for i in range(3):
            try:
                session = manager.create_session(**details)
                yield session
                break
            except ChannelError:
                # This seems to be because of the contaiener setup, so we just add
                # a little sleep in
                time.sleep(2)
        else:
            raise Exception("failed to connect to container")


@pytest.fixture(params=["windows", "ubuntu", "centos"])
def session(request):
    """ Start a session with any platform """
    yield from session_for(request)


@pytest.fixture(params=["windows"])
def windows(request):
    """ Start a windows session """
    yield from session_for(request)


@pytest.fixture(params=["ubuntu", "centos"])
def linux(request):
    """ Start a linux session """

    yield from session_for(request)
