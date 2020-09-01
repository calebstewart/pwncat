#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class ArchData:
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.

    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    arch: str
    """ The determined architecture. """

    def __str__(self):
        return f"Running on a [cyan]{self.arch}[/cyan] processor"


class Module(EnumerateModule):
    """
    Enumerate kernel/OS version information
    :return:
    """

    PROVIDES = ["system.arch"]

    def enumerate(self):
        """
        Enumerate kernel/OS version information
        :return:
        """

        try:
            result = pwncat.victim.env(["uname", "-m"]).decode("utf-8").strip()
        except FileNotFoundError:
            return

        yield "system.arch", ArchData(result)
