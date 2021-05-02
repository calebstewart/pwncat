#!/usr/bin/env python3
import dataclasses
from typing import List

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class FstabEntry:

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
                f"[blue]{self.spec}[/blue] [green]mounted[/green] at "
                f"[yellow]{self.target}[/yellow] "
                f"as [cyan]{self.fstype}[/cyan]"
            )
        else:
            return (
                f"[blue]{self.spec}[/blue] [red]available[/red] to "
                f"mount at [yellow]{self.target}[/yellow] "
                f"as [cyan]{self.fstype}[/cyan]"
            )


class Module(EnumerateModule):
    """
    Read /etc/fstab and report on known block device mount points.
    """

    PROVIDES = ["system.mountpoint"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self):

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
                    yield "system.mountpoint", FstabEntry(
                        spec, target, fstype, options.split(","), freq, passno, False
                    )
        except (FileNotFoundError, PermissionError):
            pass
