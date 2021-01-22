#!./env/bin/python
import subprocess

import pwncat.manager
import pwncat.platform.windows
import time
import stat

# Create a manager
manager = pwncat.manager.Manager("data/pwncatrc")

# Establish a session
# session = manager.create_session("windows", host="192.168.56.10", port=4444)
# session = manager.create_session("windows", host="192.168.122.11", port=4444)
# session = manager.create_session("linux", host="127.0.0.1", port=4444)
session = manager.create_session("windows", host="0.0.0.0", port=4444)

# hosts = (
#     session.platform.Path("C:\\") / "Windows" / "System32" / "drivers" / "etc" / "hosts"
# )
# with hosts.open() as filp:
#     manager.log("Read etc hosts:")
#     manager.log(filp.read())
#
# p = session.platform.Popen(["whoami.exe"], stdout=subprocess.PIPE, text=True)
# manager.log(f"Current user: {p.communicate()[0].strip()}")
# manager.log(f"Process Exit Status: {p.returncode}")

s = session.platform.stat("C:\\Windows\\System32\\drivers\\etc\\hosts")
manager.log(f"File Attributes: {s.st_file_attributes:08x}")
manager.log("File Is a Directory? " + str(stat.S_ISDIR(s.st_mode)))
manager.log("File Is Regular? " + str(stat.S_ISREG(s.st_mode)))

# downloads = session.platform.Path("C:\\Users\\caleb\\Downloads")

# for f in downloads.iterdir():
#     manager.log(f)

# manager.interactive()
