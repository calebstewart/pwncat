#!/usr/bin/env python3
import dataclasses
import re
from typing import Generator, Optional, List

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "sudo"
provides = "sudo"
per_user = True
sudo_pattern = re.compile(
    r"""(%?[a-zA-Z][a-zA-Z0-9_]*)\s+([a-zA-Z_][-a-zA-Z0-9_.]*)\s*="""
    r"""(\([a-zA-Z_][-a-zA-Z0-9_]*(:[a-zA-Z_][a-zA-Z0-9_]*)?\)|[a-zA-Z_]"""
    r"""[a-zA-Z0-9_]*)?\s+((NOPASSWD:\s+)|(SETENV:\s+)|(sha[0-9]{1,3}:"""
    r"""[-a-zA-Z0-9_]+\s+))*(.*)"""
)


@dataclasses.dataclass
class SudoSpec(FactData):

    line: str
    """ The full, unaltered line from the sudoers file """
    matched: bool = False
    """ The regular expression match data. If this is None, all following fields
    are invalid and should not be used. """
    user: Optional[str] = None
    """ The user which this rule applies to. This is None if a group was specified """
    group: Optional[str] = None
    """ The group this rule applies to. This is None if a user was specified. """
    host: Optional[str] = None
    """ The host this rule applies to """
    runas_user: Optional[str] = None
    """ The user we are allowed to run as """
    runas_group: Optional[str] = None
    """ The GID we are allowed to run as (may be None)"""
    options: List[str] = None
    """ A list of options specified (e.g. NOPASSWD, SETENV, etc) """
    hash: str = None
    """ A hash type and value which sudo will obey """
    command: str = None
    """ The command specification """

    def __str__(self):
        display = ""

        if not self.matched:
            return self.line

        if self.user is not None:
            display += f"User [blue]{self.user}[/blue]: "
        else:
            display += f"Group [cyan]{self.group}[/cyan]: "

        display += f"[yellow]{self.command}[/yellow] as "

        if self.runas_user == "root":
            display += f"[red]root[/red]"
        elif self.runas_user is not None:
            display += f"[blue]{self.runas_user}[/blue]"

        if self.runas_group == "root":
            display += f":[red]root[/red]"
        elif self.runas_group is not None:
            display += f"[cyan]{self.runas_group}[/cyan]"

        if self.host is not None:
            display += f" on [magenta]{self.host}[/magenta]"

        if self.options:
            display += (
                " (" + ",".join(f"[green]{x}[/green]" for x in self.options) + ")"
            )

        return display

    @property
    def description(self):
        if self.matched:
            return self.line
        return None


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate sudo privileges for the current user. If able, this will
    parse `/etc/sudoers`. Otherwise, it will attempt to use `sudo -l`
    to enumerate the current user's privileges. In the latter case,
    it will utilize a defined password if available.

    :return:
    """

    directives = ["Defaults", "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias"]

    try:
        with pwncat.victim.open("/etc/sudoers", "r") as filp:
            for line in filp:
                line = line.strip()
                # Ignore comments and empty lines
                if line.startswith("#") or line == "":
                    continue

                match = sudo_pattern.search(line)
                if match is None:
                    yield SudoSpec(line, matched=False, options=[])
                    continue

                user = match.group(1)

                if user in directives:
                    yield SudoSpec(line, matched=False, options=[])
                    continue

                if user.startswith("%"):
                    group = user.lstrip("%")
                    user = None
                else:
                    group = None

                host = match.group(2)

                if match.group(3) is not None:
                    runas_user = match.group(3).lstrip("(").rstrip(")")
                    if match.group(4) is not None:
                        runas_group = match.group(4)
                        runas_user = runas_user.split(":")[0]
                    else:
                        runas_group = None
                    if runas_user == "":
                        runas_user = "root"
                else:
                    runas_user = "root"
                    runas_group = None

                options = []
                hash = None

                for g in map(match.group, [6, 7, 8]):
                    if g is None:
                        continue

                    options.append(g.strip().rstrip(":"))
                    if g.startswith("sha"):
                        hash = g

                command = match.group(9)

                yield SudoSpec(
                    line,
                    True,
                    user,
                    group,
                    host,
                    runas_user,
                    runas_group,
                    options,
                    hash,
                    command,
                )

        # No need to parse `sudo -l`, since can read /etc/sudoers
        return
    except (FileNotFoundError, PermissionError):
        pass

    # Check for our privileges
    try:
        result = pwncat.victim.sudo("-l").decode("utf-8")
    except PermissionError:
        return

    for line in result.split("\n"):
        line = line.rstrip()

        # Skipe header lines
        if not line.startswith(" ") and not line.startswith("\t"):
            continue

        # Strip beginning whitespace
        line = line.strip()

        # Skip things that aren't user specifications
        if not line.startswith("("):
            continue

        # Build the beginning part of a normal spec
        line = f"{pwncat.victim.current_user.name} local=" + line.strip()

        match = sudo_pattern.search(line)
        if match is None:
            yield SudoSpec(line, matched=False, options=[])
            continue

        user = match.group(1)

        if user in directives:
            yield SudoSpec(line, matched=False, options=[])
            continue

        if user.startswith("%"):
            group = user.lstrip("%")
            user = None
        else:
            group = None

        host = match.group(2)

        if match.group(3) is not None:
            runas_user = match.group(3).lstrip("(").rstrip(")")
            if match.group(4) is not None:
                runas_group = match.group(4)
                runas_user = runas_user.split(":")[0]
            else:
                runas_group = None
            if runas_user == "":
                runas_user = "root"
        else:
            runas_user = "root"
            runas_group = None

        options = []
        hash = None

        for g in map(match.group, [6, 7, 8]):
            if g is None:
                continue

            options.append(g.strip().rstrip(":"))
            if g.startswith("sha"):
                hash = g

        command = match.group(9)

        yield SudoSpec(
            line,
            True,
            user,
            group,
            host,
            runas_user,
            runas_group,
            options,
            hash,
            command,
        )
