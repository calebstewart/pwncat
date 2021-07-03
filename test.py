#!./env/bin/python
import json
import stat
import time
import shutil
import subprocess

import pwncat.manager
import pwncat.platform.windows

# Create a manager
with pwncat.manager.Manager("data/pwncatrc") as manager:

    # Tell the manager to create verbose sessions that
    # log all commands executed on the remote host
    # manager.config.set("verbose", True, glob=True)

    # Establish a session
    # session = manager.create_session("windows", host="192.168.56.10", port=4444)
    # session = manager.create_session("windows", host="192.168.122.11", port=4444)
    # session = manager.create_session("linux", host="pwncat-ubuntu", port=4444)
    session = manager.create_session("linux", host="127.0.0.1", port=4444)

    # session.platform.powershell("amsiutils")

    with open("/tmp/random", "rb") as source:
        with session.platform.open("/tmp/random", "wb") as destination:
            shutil.copyfileobj(source, destination)

    manager.interactive()
