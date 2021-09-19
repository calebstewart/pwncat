#!/usr/bin/env python3
import json
import subprocess

import pytest
import pkg_resources

from pwncat.util import random_string
from pwncat.gtfobins import Stream, Capability
from pwncat.platform.linux import LinuxReader, LinuxWriter


def do_file_test(session, content):
    """Do a generic file test"""

    name = random_string() + ".txt"
    mode = "b" if isinstance(content, bytes) else ""

    with session.platform.open(name, mode + "w") as filp:
        assert filp.write(content) == len(content)

    with session.platform.open(name, mode + "r") as filp:
        assert filp.read() == content

    # In some cases, the act of reading/writing causes a shell to hang
    # so double check that.
    result = session.platform.run(
        ["echo", "hello world"], capture_output=True, text=True
    )
    assert result.stdout == "hello world\n"


def test_small_text(session):
    """Test writing a small text-only file"""

    do_file_test(session, "hello world")


def test_large_text(session):
    """Test writing and reading a large text file"""

    contents = ("A" * 1000 + "\n") * 10
    do_file_test(session, contents)


def test_small_binary(session):
    """Test writing a small amount of binary data"""

    contents = bytes(list(range(32)))
    do_file_test(session, contents)


def test_large_binary(session):

    contents = bytes(list(range(32))) * 400
    do_file_test(session, contents)


# Load the GTFObins database to get test cases
with open(pkg_resources.resource_filename("pwncat", "data/gtfobins.json")) as filp:
    gtfobins = json.load(filp)
    gtfobin_raw_writers = [
        key
        for key, payloads in gtfobins.items()
        if any(
            [
                payload["type"] == "write"
                and "stream" in payload
                and payload["stream"] == "raw"
                for payload in payloads
            ]
        )
    ]
    gtfobin_print_writers = [
        key
        for key, payloads in gtfobins.items()
        if any(
            [
                payload["type"] == "write"
                and ("stream" not in payload or payload["stream"] == "print")
                for payload in payloads
            ]
        )
    ]
    gtfobin_raw_readers = [
        key
        for key, payloads in gtfobins.items()
        if any(
            [
                payload["type"] == "read"
                and "stream" in payload
                and payload["stream"] == "raw"
                for payload in payloads
            ]
        )
    ]
    gtfobin_print_readers = [
        key
        for key, payloads in gtfobins.items()
        if any(
            [
                payload["type"] == "read"
                and ("stream" not in payload or payload["stream"] == "print")
                for payload in payloads
            ]
        )
    ]
    gtfobin_shells = [
        key
        for key, payloads in gtfobins.items()
        if len([payload["type"] == "shell" for payload in payloads])
    ]


@pytest.mark.parametrize("binary", gtfobin_print_readers)
def test_gtfobin_read_print(binary, linux):

    # Find the local binary
    binary_path = linux.platform.which(binary)

    # Skip if binary not available
    if binary_path is None:
        pytest.skip("binary not available")

    for method in linux.platform.gtfo.iter_binary(
        binary_path, caps=Capability.READ, stream=Stream.PRINT
    ):
        payload, input_data, exit_cmd = method.build(
            gtfo=linux.platform.gtfo, lfile="/tests/print", suid=False
        )

        popen = linux.platform.Popen(
            payload,
            shell=True,
            stdin=subprocess.PIPE,
            bootstrap_input=input_data.encode("utf-8"),
        )
        stream = LinuxReader(
            popen,
            on_close=lambda filp: filp.popen.platform.channel.send(
                exit_cmd.encode("utf-8")
            ),
            name="/tests/print",
        )

        with stream:
            assert stream.read() == "Hello\nWorld".encode("utf-8")


@pytest.mark.parametrize("binary", gtfobin_raw_readers)
def test_gtfobin_read_raw(binary, linux):

    # Find the local binary
    binary_path = linux.platform.which(binary)

    # Skip if binary not available
    if binary_path is None:
        pytest.skip("binary not available")

    for method in linux.platform.gtfo.iter_binary(
        binary_path, caps=Capability.READ, stream=Stream.RAW
    ):
        payload, input_data, exit_cmd = method.build(
            gtfo=linux.platform.gtfo, lfile="/tests/raw", suid=False
        )

        popen = linux.platform.Popen(
            payload,
            shell=True,
            stdin=subprocess.PIPE,
            bootstrap_input=input_data.encode("utf-8"),
        )
        stream = LinuxReader(
            popen,
            on_close=lambda filp: filp.popen.platform.channel.send(
                exit_cmd.encode("utf-8")
            ),
            name="/tests/raw",
        )

        with stream:
            assert stream.read() == bytes(list(range(256)))


@pytest.mark.parametrize("binary", gtfobin_raw_writers)
def test_gtfobin_write_raw(binary, linux):

    # Find the local binary
    binary_path = linux.platform.which(binary)

    # Skip if binary not available
    if binary_path is None:
        pytest.skip("binary not available")

    for method in linux.platform.gtfo.iter_binary(
        binary_path, caps=Capability.WRITE, stream=Stream.RAW
    ):
        payload, input_data, exit_cmd = method.build(
            gtfo=linux.platform.gtfo, lfile="/tmp/write_raw", suid=False
        )

        popen = linux.platform.Popen(
            payload,
            shell=True,
            stdin=subprocess.PIPE,
            bootstrap_input=input_data.encode("utf-8"),
        )
        stream = LinuxWriter(
            popen,
            on_close=lambda filp: filp.popen.platform.channel.send(
                exit_cmd.encode("utf-8")
            ),
            name="/tmp/write_raw",
        )

        with stream:
            assert stream.write(bytes(list(range(256)))) == 256

    with linux.platform.open("/tmp/write_raw", "rb") as filp:
        assert filp.read() == bytes(list(range(256)))

    linux.platform.unlink("/tmp/write_raw")


@pytest.mark.parametrize("binary", gtfobin_print_writers)
def test_gtfobin_write_print(binary, linux):

    content = b"Hello\nWorld"

    # Find the local binary
    binary_path = linux.platform.which(binary)

    # Skip if binary not available
    if binary_path is None:
        pytest.skip("binary not available")

    for method in linux.platform.gtfo.iter_binary(
        binary_path, caps=Capability.WRITE, stream=Stream.PRINT
    ):
        payload, input_data, exit_cmd = method.build(
            gtfo=linux.platform.gtfo, lfile="/tmp/write_print", suid=False
        )

        popen = linux.platform.Popen(
            payload,
            shell=True,
            stdin=subprocess.PIPE,
            bootstrap_input=input_data.encode("utf-8"),
        )
        stream = LinuxWriter(
            popen,
            on_close=lambda filp: filp.popen.platform.channel.send(
                exit_cmd.encode("utf-8")
            ),
            name="/tmp/write_print",
        )

        with stream:
            assert stream.write(content) == len(content)

    with linux.platform.open("/tmp/write_print", "rb") as filp:
        assert filp.read() == content

    linux.platform.unlink("/tmp/write_print")


# @pytest.mark.parametrize("binary", gtfobin_writers)
# def test_gtfobin_write(binary, session):
#
#     # Skip if binary not available
#     if session.platform.which(binary) is None:
#         pytest.skip("binary not available")
#
#     return
#
#
# @pytest.mark.parametrize("binary", gtfobin_shells)
# def test_gtfobin_shell(binary, session):
#
#     # Skip if binary not available
#     if session.platform.which(binary) is None:
#         pytest.skip("binary not available")
#
#     return
