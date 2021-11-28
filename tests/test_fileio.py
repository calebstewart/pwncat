#!/usr/bin/env python3

from pwncat.util import random_string


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
    assert len(list(session.platform.Path("/").iterdir())) > 0


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
