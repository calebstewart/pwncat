#!/usr/bin/env python3
import pwncat.platform
from pwncat import subprocess
from pwncat.util import console
import hashlib
import os

try:
    # Open a connection to a linux platform
    # This will automatically open a new channel with the specified arguments.
    target = pwncat.platform.create("linux", host="pwncat-centos-testing", port=4444)
except pwncat.channel.ChannelError as exc:
    console.log(f"[red]error[/red]: platform.create: {exc}")

try:
    # Ensure we have a PTY on the new shell (not required, but we want to
    # make sure it's working)
    target.get_pty()
except pwncat.channel.ChannelError as exc:
    console.log(f"[red]error[/red]: get_pty: {exc}")

# Generate random data
count = 8192
data = os.urandom(count)
sum = hashlib.md5(data).hexdigest()

console.log(f"writing {count}-bytes of random data to /tmp/write-test")
console.log(f"data hashsum: {sum}")

# Open the file and write the data
with target.open("/tmp/write-test", "w") as filp:
    filp.write(data)

console.log("reading /tmp/write-test and checking hashsum")

# Read the file back
with target.open("/tmp/write-test", "r") as filp:
    data = filp.read()

# Calculate the hash sum of the data we read back
new_sum = hashlib.md5(data).hexdigest()

console.log(f"hashsum of read data: {new_sum}")

# Ensure they match
if sum != new_sum:
    console.log("[red]error[/red]: hash mismatch!")

# print(
#     target.Popen(
#         "stty -a", shell=True, text=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE
#     ).communicate()[0]
# )

# # Try to write to a file with `dd`
# p = target.Popen(["cat", "-"], stdout="/tmp/test", stdin=subprocess.PIPE,)
#
# # Write every possible 7-bit character (where control codes reside)
# for i in range(127):
#     p.stdin.write(bytes([0x16, i]))
#
# # Send CTRL-D to stop it
# p.stdin.write(b"\x04\x04")
#
# # Grab the output of dd
# stdout, _ = p.communicate()
# print(stdout)
#
# # Get the content of the file
# p = target.Popen(["hexdump", "/tmp/test"], stdout=subprocess.PIPE, text=True)
# print(p.communicate()[0])
