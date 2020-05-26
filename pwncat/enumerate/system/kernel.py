#!/usr/bin/env python3
import dataclasses
from typing import Generator, List

from colorama import Fore

from pwncat.enumerate import FactData
from pwncat import util
import pwncat

name = "pwncat.enumerate.system"
provides = "system.version.kernel"
per_user = False


@dataclasses.dataclass
class KernelVersion(FactData):
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.
    
    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    major: int
    minor: int
    patch: int
    abi: str

    def __str__(self):
        return (
            f"Running Linux Kernel {Fore.RED}{self.major}{Fore.RESET}."
            f"{Fore.GREEN}{self.minor}{Fore.RESET}."
            f"{Fore.BLUE}{self.patch}{Fore.RESET}-{Fore.CYAN}{self.abi}{Fore.RESET}"
        )


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate kernel/OS version information
    :return:
    """

    # Try to find kernel version number
    try:
        kernel = pwncat.victim.env(["uname", "-r"]).strip().decode("utf-8")
        if kernel == "":
            raise FileNotFoundError
    except FileNotFoundError:
        try:
            with pwncat.victim.open("/proc/version", "r") as filp:
                kernel = filp.read()
        except (PermissionError, FileNotFoundError):
            kernel = None

    # Parse the kernel version number
    if kernel is not None:
        kernel = kernel.strip()
        # We got the full "uname -a" style output
        if kernel.lower().startswith("linux"):
            kernel = kernel.split(" ")[2]

        # Split out the sections
        w, x, *y_and_z = kernel.split(".")
        y_and_z = ".".join(y_and_z).split("-")
        y = y_and_z[0]
        z = "-".join(y_and_z[1:])

        yield KernelVersion(int(w), int(x), int(y), z)
