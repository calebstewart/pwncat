#!./env/bin/python
import subprocess

import pwncat.manager
import pwncat.platform.windows
import time
import stat
import json

# Create a manager
manager = pwncat.manager.Manager("data/pwncatrc")

# Establish a session
# session = manager.create_session("windows", host="192.168.56.10", port=4444)
session = manager.create_session("windows", host="192.168.122.11", port=4444)
# session = manager.create_session("linux", host="127.0.0.1", port=4444)
# session = manager.create_session("windows", host="0.0.0.0", port=4444)

manager.interactive()
