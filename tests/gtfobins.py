#!/usr/bin/env python3
from colorama import Fore, Style
import subprocess
import argparse
import shlex
import sys
import os

# Add the parent directory to find pwncat
sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), "..")))

# Import pwncat
from pwncat.gtfobins import GTFOBins, Capability, Stream

stream_names = [x.lower() for x in Stream._member_map_]
capability_names = [x.lower() for x in Capability._member_map_]


def CapabilityType(value: str) -> Capability:
    values = [v.strip() for v in value.split("|")]
    result = Capability.NONE
    for v in values:
        if v.upper() not in Capability._member_map_:
            raise argparse.ArgumentTypeError(f"{v}: invalid capability")
        result |= Capability._member_map_[v.upper()]

    return result


def StreamType(value: str) -> Stream:
    values = [v.strip() for v in value.split("|")]
    result = Stream.NONE
    for v in values:
        if v.upper() not in Stream._member_map_:
            raise argparse.ArgumentTypeError(f"{v}: invalid capability")
        result |= Stream._member_map_[v.upper()]

    return result


parser = argparse.ArgumentParser(
    prog="gtfobins.py", description="Test gtfobins payloads locally"
)
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument(
    "--find",
    "-f",
    action="store_true",
    help="Search for a capability in any local binaries",
)
group.add_argument("--binary", "-b", help="Find a capability in the specified binary")
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "--show", default=True, action="store_true", help="Show the generated payload(s)"
)
group.add_argument(
    "--execute", "-e", action="store_true", help="Execute the payload(s) locally"
)

parser.add_argument("--path", "-p", help="The local file name to read or write")
parser.add_argument("--length", "-l", type=int, help="The length the data to write")
parser.add_argument(
    "--shell", "-s", help="The local shell to start", default="/bin/bash"
)
parser.add_argument("--data", "-d", help="The local data to write to the remote file")
parser.add_argument(
    "--capability",
    "-c",
    help="Bitwise OR'd capabilities to find",
    default=Capability.ALL,
    type=CapabilityType,
)
parser.add_argument(
    "--stream",
    "-S",
    help="Bitwise OR'd stream types to find",
    default=Stream.ANY,
    type=StreamType,
)
parser.add_argument("--spec", default=None, help="A sudo command specification")
parser.add_argument(
    "--user", default=None, help="A user to run the command as with sudo"
)
parser.add_argument(
    "--suid", action="store_true", default=False, help="Generate a SUID payload"
)

args = parser.parse_args()


def local_which(path: str, quote: bool = True):
    try:
        result = (
            subprocess.check_output(f"which {shlex.quote(path)}", shell=True)
            .decode("utf-8")
            .strip()
        )
    except subprocess.CalledProcessError:
        return None

    if result == "":
        return None

    if quote:
        result = shlex.quote(result)

    return result


gtfo = GTFOBins("../pwncat/data/gtfobins.json", local_which)

if args.find:
    if not args.spec:
        methods = list(gtfo.iter_methods(args.capability, args.stream, spec=args.spec))
    else:
        methods = list(gtfo.iter_sudo(args.spec, args.capability, args.stream))
else:
    if not os.path.exists(args.binary) and not args.binary.startswith("/"):
        binary_path = local_which(args.binary)
        if not binary_path:
            parser.error(f"{args.binary}: no such file or directory")
    elif not os.path.exists(args.binary):
        parser.error(f"{args.binary}: no such file or directory")
    else:
        binary_path = args.binary
    methods = list(
        gtfo.iter_binary(binary_path, args.capability, args.stream, args.spec)
    )

for method in methods:
    print(
        f"{Style.BRIGHT}{Fore.RED}{method.cap.name}{Fore.RESET} via {method.binary_path}{Style.RESET_ALL}"
    )
    payload, input_data, exit_cmd = method.build(
        lfile=args.path,
        length=args.length,
        shell=args.shell,
        suid=args.suid,
        user=args.user,
        spec=args.spec,
    )
    print(f" Payload: {payload}")
    print(f" Input: {repr(input_data)}")
    print(f" Exit Command: {repr(exit_cmd)}")
