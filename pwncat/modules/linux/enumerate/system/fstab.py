#!/usr/bin/env python3
import dataclasses
from typing import List

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule, Schedule


class FstabEntry(Fact):
    def __init__(self, source, spec, target, fstype, options, freq, passno, mounted):
        super().__init__(source=source, types=["system.mountpoint"])

        self.spec: str = spec
        """ The FS Specification (e.g. /dev/sda1 or UUID=XXXX) """
        self.target: str = target
        """ The target location for this mount (e.g. /mnt/mydisk or /home) """
        self.fstype: str = fstype
        """ The type of filesystem being mounted (e.g. ext4 or bind) """
        self.options: List[str] = options
        """ The list of options associated with this mount (split on comma) """
        self.freq: int = freq
        """ Whether to dump this filesystem (defaults to zero, fifth field, see fstab(5)) """
        self.passno: int = passno
        """ Order of fsck at boot time. See fstab(5) and fsck(8). """
        self.mounted: bool = mounted
        """ Whether this is currently mounted (not from fstab, but cross-referenced w/ /proc/mount) """

    def title(self, session):
        if self.mounted:
            return (
                f"[blue]{rich.markup.escape(self.spec)}[/blue] [green]mounted[/green] at "
                f"[yellow]{rich.markup.escape(self.target)}[/yellow] "
                f"as [cyan]{rich.markup.escape(self.fstype)}[/cyan]"
            )
        else:
            return (
                f"[blue]{rich.markup.escape(self.spec)}[/blue] [red]available[/red] to "
                f"mount at [yellow]{rich.markup.escape(self.target)}[/yellow] "
                f"as [cyan]{rich.markup.escape(self.fstype)}[/cyan]"
            )


class Module(EnumerateModule):
    """
    Read /etc/fstab and report on known block device mount points.
    """

    PROVIDES = ["system.mountpoint"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):

        try:
            with session.platform.open("/etc/fstab", "r") as filp:
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
                        self.name,
                        spec,
                        target,
                        fstype,
                        options.split(","),
                        freq,
                        passno,
                        False,
                    )
        except (FileNotFoundError, PermissionError):
            pass
