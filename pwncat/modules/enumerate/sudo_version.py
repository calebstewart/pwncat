#!/usr/bin/env python3
import dataclasses
import re

from pwncat.modules.enumerate import EnumerateModule, Schedule
import pwncat
from pwncat.platform import Platform


@dataclasses.dataclass
class SudoVersion:
    """
    Version of the installed sudo binary may be useful for exploitation

    """

    version: str
    output: str
    vulnerable: bool

    def __str__(self):
        result = f"[yellow]sudo[/yellow] version [cyan]{self.version}[/cyan]"
        if self.vulnerable:
            result += f" (may be [red]vulnerable[/red])"
        return result

    @property
    def description(self):
        result = self.output
        if self.vulnerable:
            result = result.rstrip("\n") + "\n\n"
            result += (
                f'This version may be vulnerable. Check against "searchsploit sudo"'
            )
        return result


class Module(EnumerateModule):

    PROVIDES = ["sudo.version"]
    PLATFORM = Platform.LINUX
    SCHEDULE = Schedule.ONCE

    def enumerate(self):
        """
        Enumerate kernel/OS version information
        :return:
        """

        try:
            # Check the sudo version number
            result = pwncat.victim.env(["sudo", "--version"]).decode("utf-8").strip()
        except FileNotFoundError:
            return

        # Taken from here:
        #   https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version
        known_vulnerable = [
            "1.6.8p9",
            "1.6.9p18",
            "1.8.14",
            "1.8.20",
            "1.6.9p21",
            "1.7.2p4",
            "1.8.0",
            "1.8.1",
            "1.8.2",
            "1.8.3",
            "1.4",
            "1.5",
            "1.6",
        ]

        # Can we match this output to a specific sudo version?
        match = re.search(
            r"sudo version ([0-9]+\.[0-9]+\.[^\s]*)", result, re.IGNORECASE
        )
        if match is not None and match.group(1) is not None:
            vulnerable = False
            # Is this in our list of known vulnerable versions? Not a guarantee, but
            # a rough quick check.
            for v in known_vulnerable:
                if match.group(1).startswith(v):
                    vulnerable = True
                    break

            yield "sudo.version", SudoVersion(match.group(1), result, vulnerable)
            return

        # We couldn't parse the version out, but at least give the full version
        # output in the long form/report of enumeration.
        yield "sudo.version", SudoVersion("unknown", result, False)
