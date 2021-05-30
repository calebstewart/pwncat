#!/usr/bin/env python3
import io

import pwncat.manager


def test_config_fileobj():

    configuration = io.StringIO(
        """
set -g db "memory://"
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
            filp.writelines(["""set -g backdoor_user "config_test"\n"""])

        os.chdir(tmp_path)

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
