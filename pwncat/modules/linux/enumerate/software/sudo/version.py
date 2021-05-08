#!/usr/bin/env python3
import dataclasses
import re

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.subprocess import CalledProcessError
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule


class SudoVersion(Fact):
    """
    Version of the installed sudo binary may be useful for exploitation

    """

    def __init__(self, source, version, output, vulnerable):
        super().__init__(source=source, types=["software.sudo.version"])

        self.version: str = version
        self.output: str = output
        self.vulnerable: bool = vulnerable

    def __str__(self):
        result = f"[yellow]sudo[/yellow] version [cyan]{rich.markup.escape(self.version)}[/cyan]"
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
    """
    Retrieve the version of sudo on the remote host
    """

    PROVIDES = ["software.sudo.version"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):
        """
        Enumerate the currently running version of sudo
        :return:
        """

        try:
            # Check the sudo version number
            result = session.platform.run(
                ["sudo", "--version"], capture_output=True, check=True
            )
        except CalledProcessError:
            # Something went wrong with the sudo version
            return

        version = result.stdout.decode("utf-8")

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
            r"sudo version ([0-9]+\.[0-9]+\.[^\s]*)", version, re.IGNORECASE
        )
        if match is not None and match.group(1) is not None:
            vulnerable = False
            # Is this in our list of known vulnerable versions? Not a guarantee, but
            # a rough quick check.
            for v in known_vulnerable:
                if match.group(1).startswith(v):
                    vulnerable = True
                    break

            yield SudoVersion(self.name, match.group(1), version, vulnerable)
            return

        # We couldn't parse the version out, but at least give the full version
        # output in the long form/report of enumeration.
        yield SudoVersion(self.name, "unknown", version, False)
