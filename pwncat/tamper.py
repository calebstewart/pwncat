#!/usr/bin/env python3
from typing import List, Optional, Callable, Iterator
from enum import Enum, auto
import datetime

import pwncat
from pwncat.util import Access


class Action(Enum):
    CREATE = auto()
    MODIFY = auto()
    DELETE = auto()


class RevertFailed(Exception):
    """Reversion of a tamper failed. This requires manual intervention by the user"""


class Tamper:
    def __init__(self, action: Action):
        self.action = action
        self.timestamp = datetime.datetime.now()

    def revert(self, session: "pwncat.manager.Session"):
        raise NotImplementedError


class CreatedFile(Tamper):
    """Created file tamper. Revert simply needs to remove the file."""

    def __init__(self, session: "pwncat.manager.Session", path: str):
        super(CreatedFile, self).__init__(Action.CREATE)
        self.path = path
        self.uid = session.platform.getuid()

    def revert(self, session: "pwncat.manager.Session"):

        current_uid = session.plaform.getuid()
        if current_uid != self.uid and current_uid != 0:
            raise RevertFailed(
                f"{current_uid}: invalid current uid for revert (expected {self.uid})"
            )

        try:
            session.platform.Path(self.path).unlink()
            if session.platform.Path(self.path).exists():
                raise RevertFailed(f"{self.path}: unable to remove file")
        except (PermissionError, FileNotFoundError) as exc:
            raise RevertFailed(str(exc))

    def __str__(self):
        return f"[red]Created[/red] file [cyan]{self.path}[/cyan]"


class ModifiedFile(Tamper):
    """File modification tamper. This tamper needs either a specific line which
    should be removed from a text file, or the original original_content as bytes which
    will be replaced. If neither is provided, we will track the modification but be unable
    to revert it."""

    def __init__(
        self,
        session: "pwncat.manager.Session",
        path: str,
        added_lines: List[str] = None,
        original_content: bytes = None,
    ):
        super(ModifiedFile, self).__init__(Action.MODIFY)

        self.path = path
        self.added_lines = added_lines
        self.original_content = original_content
        self.uid = session.platform.getuid()

    def revert(self, session: "pwncat.manager.Session"):

        if session.platform.getuid() == self.uid:
            raise RevertFailed("invalid current uid for revert")

        try:
            if self.added_lines:
                # Read the current lines
                with session.platform.open(self.path, "r") as filp:
                    lines = [
                        line
                        for line in filp.readlines()
                        if line not in self.added_lines
                    ]

                with session.platform.open(self.path, "w") as filp:
                    filp.write("".join(lines))

            elif self.original_content:
                with session.platform.open(self.path, "wb") as filp:
                    filp.write(self.original_content)
            else:
                raise RevertFailed("no original_content or added_lines")
        except (PermissionError, FileNotFoundError) as exc:
            raise RevertFailed(str(exc))

    def __str__(self):
        return f"[red]Modified[/red] [cyan]{self.path}[/cyan]"

    def __repr__(self):
        return f"ModifiedFile(path={self.path})"


class LambdaTamper(Tamper):
    def __init__(
        self,
        name: str,
        revert: Optional[Callable[["pwncat.manager.Session"], None]] = None,
    ):
        self.name = name
        self._revert = revert

    def revert(self, session: "pwncat.manager.Session"):
        if self._revert:
            self._revert(session)
        else:
            raise RevertFailed("revert not possible")

    def __str__(self):
        return self.name


class TamperManager:

    pass
