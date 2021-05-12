#!./env/bin/python
import subprocess

import pwncat.manager
import pwncat.platform.windows
import time
import stat
import json

# Create a manager
manager = pwncat.manager.Manager("data/pwncatrc")

# Tell the manager to create verbose sessions that
# log all commands executed on the remote host
# manager.config.set("verbose", True, glob=True)

# Establish a session
# session = manager.create_session("windows", host="192.168.56.10", port=4444)
# session = manager.create_session("windows", host="192.168.122.11", port=4444)
session = manager.create_session("linux", host="127.0.0.1", port=9999)
# session = manager.create_session("windows", host="0.0.0.0", port=4444)

for _ in range(30):

    data = session.platform.run(
        "cat /tmp/dummy",
        capture_output=True,
        text=True,
        check=True,
    )

    print(data.stdout.split("\n\n")[0])
    print("===================================================")
