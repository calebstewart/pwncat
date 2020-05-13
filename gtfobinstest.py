#!/usr/bin/env python3


from pwncat.gtfobins import *
import subprocess


def which(path: str, quote=False):
    try:
        output = subprocess.check_output(f"which {path}", shell=True)
    except subprocess.CalledProcessError:
        return None

    return output.decode("utf-8").strip()


gtfo = GTFOBins("data/gtfobins.json", which)

all_binaries = list(gtfo.iter_methods(Capability.SHELL))
print(all_binaries[0].build(shell="/bin/bash", suid=True))
