#!/usr/bin/env python3

import pytest

from pwncat.modules import IncorrectPlatformError


def test_session_iter_users(session):
    """Test the ability to iterate users. This happens
    implicitly with session.current_user(), but it's worth
    testing separately."""

    assert "john" in [user.name for user in session.iter_users()]


def test_session_find_user_name(session):
    """Test that locating a user by name works"""

    assert session.find_user(name="john") is not None


def test_session_find_user_uid(linux):
    """Test locating a user by their UID (for linux only)"""

    user = linux.find_user(uid=0)

    assert user is not None
    assert user.name == "root"


def test_session_find_user_sid(windows):
    """Test locating a user by their SID (for windows only)"""

    # This is the SID of the Administrator in the windows servercore image...
    # This will only work from the testing container, but I've decided that's fine.
    user = windows.find_user(uid="S-1-5-21-1417486881-3347836355-822217238-500")

    assert user is not None
    assert user.name == "Administrator"


def test_session_find_module(session):
    """Test that locating modules works"""

    assert len(list(session.find_module("enumerate.*"))) > 0
    assert len(list(session.find_module("enumerate.user"))) == 1
    assert len(list(session.find_module("module_does_not_exist"))) == 0


def test_session_run_module(session):
    """Test running a module within a session"""

    # We should be able to enumerate a hostname
    facts = session.run("enumerate", types=["system.hostname"])
    assert len(facts) > 0


def test_session_wrong_platform_linux(linux):
    """Test that windows modules don't run in linux"""

    with pytest.raises(IncorrectPlatformError):
        linux.run("windows.enumerate.user")


def test_session_wrong_platform_windows(windows):
    """Test that linux modules don't run on windows"""

    with pytest.raises(IncorrectPlatformError):
        windows.run("linux.enumerate.user")
