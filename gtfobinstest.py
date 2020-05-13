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


binary_to_test = "chmod"
capabilities_to_test = Capability.SHELL
our_shell = "/bin/bash"

binary = gtfo.find_binary(binary_to_test)
print(binary)
print(vars(binary))

methods = binary.iter_methods(
    which(binary_to_test), caps=capabilities_to_test, stream=None
)
for method in methods:
    # print(method)
    print(method.build(shell=our_shell)[0])
    # print(method.build(lfile="/etc/shadow", suid=True)[0])
    # print(method.build(lfile="/tmp/test", data="hello")[0])

# all_binaries = list(gtfo.iter_methods(Capability.SHELL))
# print(all_binaries[0].build(shell="/bin/bash", suid=True))
