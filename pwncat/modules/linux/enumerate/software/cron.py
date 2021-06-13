#!/usr/bin/env python3
import os
import re
import dataclasses

import rich.markup

import pwncat
from pwncat.db import Fact
from pwncat.modules import Status
from pwncat.subprocess import CalledProcessError
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class CronEntry(Fact):
    def __init__(self, source, path, uid, command, datetime):
        super().__init__(source=source, types=["software.cron.entry"])

        self.path: str = path
        """ The path to the crontab where this was found """
        self.uid: int = uid
        """ The user ID this entry will run as """
        self.command: str = command
        """ The command that will execute """
        self.datetime: str = datetime
        """ The entire date/time specifier from the crontab entry """

    def description(self, session):
        return f"{self.path}: {self.datetime} {self.command}"

    def title(self, session):
        return f"[blue]{session.find_user(uid=self.uid).name}[/blue] runs [yellow]{repr(self.command)}[/yellow]"


def parse_crontab(
    source, session, path: str, line: str, system: bool = True
) -> CronEntry:
    """
    Parse a crontab line. This returns a tuple of (command, datetime, user) indicating
    the command to run, when it will execute, and who it will execute as. If system is
    false, then the current user is returned and no user element is parsed (assumed
    not present).

    This will raise a ValueError if the line is malformed.

    :param line: the line from crontab
    :param system: whether this is a system or user crontab entry
    :return: a tuple of (command, datetime, username)
    """

    # Variable assignment, comment or empty line
    if (
        line.startswith("#")
        or line == ""
        or re.match(r"[a-zA-Z][a-zA-Z0-9_-]*\s*=.*", line) is not None
    ):
        raise ValueError

    entry = [x for x in line.strip().replace("\t", " ").split(" ") if x != ""]

    # Malformed entry or comment
    if (len(entry) <= 5 and not system) or (len(entry) <= 6 and system):
        raise ValueError

    when = " ".join(entry[:5])

    if system:
        uid = session.find_user(name=entry[5]).id
        command = " ".join(entry[6:])
    else:
        uid = session.current_user().id
        command = " ".join(entry[5:])

    return CronEntry(source, path, uid, command, when)


class Module(EnumerateModule):
    """
    Check for any readable crontabs and return their entries.
    """

    PROVIDES = ["software.cron.entry"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session):

        try:
            # Get this user's crontab entries
            proc = session.platform.run(
                ["crontab", "-l"], capture_output=True, text=True, check=True
            )
            user_entries = proc.stdout

        except CalledProcessError as exc:
            # The crontab command doesn't exist :(
            return

        for line in user_entries.split("\n"):
            try:
                yield parse_crontab(
                    self.name, session, "crontab -l", line, system=False
                )
            except ValueError:
                continue

        known_tabs = ["/etc/crontab"]

        for tab_path in known_tabs:
            try:
                with session.platform.open(tab_path, "r") as filp:
                    for line in filp:
                        try:
                            yield parse_crontab(
                                self.name, session, tab_path, line, system=True
                            )
                        except ValueError:
                            continue
            except (FileNotFoundError, PermissionError):
                pass

        known_dirs = [
            "/etc/cron.d",
            # I'm dumb. These aren't crontabs... they're scripts...
            # "/etc/cron.daily",
            # "/etc/cron.weekly",
            # "/etc/cron.monthly",
        ]
        for dir_path in known_dirs:
            try:
                yield Status(f"getting crontabs from [cyan]{dir_path}[/cyan]")
                filenames = list(session.platform.listdir(dir_path))
                for filename in filenames:
                    if filename in (".", ".."):
                        continue
                    yield Status(f"reading [cyan]{filename}[/cyan]")
                    try:
                        with session.platform.open(
                            os.path.join(dir_path, filename), "r"
                        ) as filp:
                            for line in filp:
                                try:
                                    yield parse_crontab(
                                        self.name,
                                        session,
                                        os.path.join(dir_path, filename),
                                        line,
                                        system=True,
                                    )
                                except ValueError:
                                    pass
                    except (FileNotFoundError, PermissionError):
                        pass
            except (FileNotFoundError, NotADirectoryError, PermissionError):
                pass
