#!/usr/bin/env python3
import io

import pwncat.manager


def test_config_fileobj():

    configuration = io.StringIO(
        """
set -g db "sqlite://:memory:"
set -g prefix c-k
set -g on_load {  }
set -g backdoor_user "config_test"
    """
    )

    with pwncat.manager.Manager(config=configuration) as manager:
        assert manager.config["backdoor_user"] == "config_test"


def test_user_config(tmp_path):

    import os

    # Ensure we don't muck up the environment for this process
    old_home = os.environ.get("XDG_DATA_HOME", None)

    try:
        # Set the data home to our temp path
        os.environ["XDG_DATA_HOME"] = str(tmp_path)

        # Create the pwncat directory
        (tmp_path / "pwncat").mkdir(exist_ok=True, parents=True)

        # Create our user configuration
        with (tmp_path / "pwncat" / "pwncatrc").open("w") as filp:
            filp.write(
                """
set -g backdoor_user "config_test"
            """
            )

        # Create a manager object with default config to load our
        # user configuration.
        with pwncat.manager.Manager(config=None) as manager:
            assert manager.config["backdoor_user"] == "config_test"
    finally:
        # Restore the environment
        if old_home is not None:
            os.environ["XDG_DATA_HOME"] = old_home
        else:
            del os.environ["XDG_DATA_HOME"]


def test_multisession(linux):

    # Create a manager with the default configuration
    with pwncat.manager.Manager(config=None) as manager:

        # Connect to the target twice to get two sessions
        session1 = manager.create_session(**linux)
        session2 = manager.create_session(**linux)

        # Ensure both sessions are tracked
        assert len(manager.sessions) == 2

        # Ensure they match what was returned by create_session
        assert session1 in manager.sessions
        assert session2 in manager.sessions

        # Ensure creating a session sets the current target
        assert manager.target == session2

        # Switch targets
        manager.target = session1

        # Ensure we are now tracking the expected target
        assert manager.target == session1
