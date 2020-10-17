#!/usr/bin/env python3
import pwncat.platform
from pwncat import subprocess
from pwncat.util import console

try:
    target = pwncat.platform.create("linux", host="pwncat-centos-testing", port=4444)
except pwncat.channel.ChannelError as exc:
    console.log(f"[red]error[/red]: platform.create: {exc}")

try:
    target.get_pty()
except pwncat.channel.ChannelError as exc:
    console.log(f"[red]error[/red]: get_pty: {exc}")

p = target.Popen(
    ["ls", "--format=single-column", "/home"], encoding="utf-8", stdout=subprocess.PIPE
)

for name in p.stdout:
    console.log(name)

console.log(f"ls exited with return code {p.wait()}")
