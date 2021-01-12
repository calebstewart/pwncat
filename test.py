#!./env/bin/python
import subprocess

import pwncat.manager
import pwncat.platform.windows
import time

# Create a manager
manager = pwncat.manager.Manager("data/pwncatrc")

# Establish a session
session = manager.create_session("windows", host="192.168.56.10", port=4444)
# session = manager.create_session("windows", host="192.168.122.11", port=4444)

hosts = (
    session.platform.Path("C:\\") / "Windows" / "System32" / "drivers" / "etc" / "hosts"
)
with hosts.open() as filp:
    manager.log("Read etc hosts:")
    manager.log(filp.read())

p = session.platform.Popen(["whoami.exe"], stdout=subprocess.PIPE, text=True)
manager.log(f"Current user: {p.communicate()[0].strip()}")
manager.log(f"Process Exit Status: {p.returncode}")

manager.interactive()
