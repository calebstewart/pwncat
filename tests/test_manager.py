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

    # Create our user configuration
    with (tmp_path / "pwncatrc").open("w") as filp:
        filp.writelines(["""set -g backdoor_user "config_test"\n"""])

    # Create a manager object with default config to load our
    # user configuration.
    with pwncat.manager.Manager(config=str(tmp_path / "pwncatrc")) as manager:
        assert manager.config["backdoor_user"] == "config_test"
