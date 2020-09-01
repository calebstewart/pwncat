#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule

@dataclasses.dataclass
class KernelVersionData:
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
            f"Running Linux Kernel [red]{self.major}[/red]."
            f"[green]{self.minor}[/green]."
            f"[blue]{self.patch}[/blue]-[cyan]{self.abi}[/cyan]"
        )

class Module(EnumerateModule):
    """
    Enumerate kernel/OS version information
    :return:
    """
    PROVIDES = ["kernel"]

    def enumerate(self):

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

            yield "kernel", KernelVersionData(int(w), int(x), int(y), z)
