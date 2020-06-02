#!/usr/bin/env python3
import dataclasses
from typing import Generator, List

from colorama import Fore

from pwncat.enumerate import FactData
import pwncat

name = "pwncat.enumerate.fstab"
provides = "system.fstab"
per_user = False


@dataclasses.dataclass
class FstabEntry(FactData):

    spec: str
    """ The FS Specification (e.g. /dev/sda1 or UUID=XXXX) """
    target: str
    """ The target location for this mount (e.g. /mnt/mydisk or /home) """
    fstype: str
    """ The type of filesystem being mounted (e.g. ext4 or bind) """
    options: List[str]
    """ The list of options associated with this mount (split on comma) """
    freq: int
    """ Whether to dump this filesystem (defaults to zero, fifth field, see fstab(5)) """
    passno: int
    """ Order of fsck at boot time. See fstab(5) and fsck(8). """
    mounted: bool
    """ Whether this is currently mounted (not from fstab, but cross-referenced w/ /proc/mount) """

    def __str__(self):
        if self.mounted:
            return (
                f"{Fore.BLUE}{self.spec}{Fore.RESET} {Fore.GREEN}mounted{Fore.RESET} at "
                f"{Fore.YELLOW}{self.target}{Fore.RESET} "
                f"as {Fore.CYAN}{self.fstype}{Fore.RESET}"
            )
        else:
            return (
                f"{Fore.BLUE}{self.spec}{Fore.RESET} {Fore.RED}available{Fore.RESET} to "
                f"mount at {Fore.YELLOW}{self.target}{Fore.RESET} "
                f"as {Fore.CYAN}{self.fstype}{Fore.RESET}"
            )

    @property
    def description(self):
        return "\t".join(
            [
                self.spec,
                self.target,
                self.fstype,
                ",".join(self.options),
                str(self.freq),
                str(self.passno),
            ]
        )


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate filesystems in /etc/fstab. At some point, this should mark
    file systems with their mount status, but I'm not sure how to resolve
    the UUID= entries intelligently right now, so for now it just results
    in returning the entries in the fstab.

    :return:
    """

    try:
        with pwncat.victim.open("/etc/fstab", "r") as filp:
            for line in filp:
                line = line.strip()
                if line.startswith("#") or line == "":
                    continue
                try:
                    spec, target, fstype, options, *entries = line.split()
                    # Optional entries
                    freq = int(entries[0]) if entries else "0"
                    passno = int(entries[1]) if len(entries) > 1 else "0"
                except (ValueError, IndexError):
                    # Badly formatted line
                    continue
                yield FstabEntry(
                    spec, target, fstype, options.split(","), freq, passno, False
                )
    except (FileNotFoundError, PermissionError):
        pass
