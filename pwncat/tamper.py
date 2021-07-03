#!/usr/bin/env python3
import pickle
from typing import List, Optional, Callable, Iterator
from enum import Enum, auto
from colorama import Fore

import pwncat
from pwncat.util import Access


class Action(Enum):
    CREATE = auto()
    MODIFY = auto()
    DELETE = auto()


class RevertFailed(Exception):
    """ Reversion of a tamper failed. This requires manual intervention by the user """


class Tamper:
    def __init__(self, action: Action):
        self.action = action

    def revert(self):
        raise NotImplementedError


class CreatedFile(Tamper):
    """ Created file tamper. Revert simply needs to remove the file. """

    def __init__(self, path: str):
        super(CreatedFile, self).__init__(Action.CREATE)
        self.path = path

    def revert(self):
        try:
            pwncat.victim.run(f"rm -f {self.path}")
            if Access.EXISTS in pwncat.victim.access(self.path):
                raise RevertFailed(f"{self.path}: unable to remove file")
        except (PermissionError, FileNotFoundError) as exc:
            raise RevertFailed(str(exc))

    def __str__(self):
        return f"[red]Created[/red] file [cyan]{self.path}[/cyan]"


class ModifiedFile(Tamper):
    """ File modification tamper. This tamper needs either a specific line which
    should be removed from a text file, or the original original_content as bytes which
    will be replaced. If neither is provided, we will track the modification but be unable
    to revert it. """

    def __init__(
        self, path: str, added_lines: List[str] = None, original_content: bytes = None
    ):
        super(ModifiedFile, self).__init__(Action.MODIFY)

        self.path = path
        self.added_lines = added_lines
        self.original_content = original_content

    def revert(self):
        try:
            if self.added_lines:
                # Read the current lines
                with pwncat.victim.open(self.path, "r") as filp:
                    lines = filp.readlines()

                # Remove matching lines
                for line in self.added_lines:
                    try:
                        lines.remove(line)
                    except ValueError:
                        pass

                # Write the new original_content
                file_data = "".join(lines)
                with pwncat.victim.open(self.path, "w", length=len(file_data)) as filp:
                    filp.write(file_data)

            elif self.original_content:
                with pwncat.victim.open(
                    self.path, "wb", length=len(self.original_content)
                ) as filp:
                    filp.write(self.original_content)
            else:
                raise RevertFailed("no original_content or added_lines specified")
        except (PermissionError, FileNotFoundError) as exc:
            raise RevertFailed(str(exc))

    def __str__(self):
        return f"[red]Modified[/red] [cyan]{self.path}[/cyan]"

    def __repr__(self):
        return f"ModifiedFile(path={self.path})"


class LambdaTamper(Tamper):
    def __init__(self, name: str, revert: Optional[Callable] = None):
        self.name = name
        self._revert = revert

    def revert(self):
        if self._revert:
            self._revert()
        else:
            raise RevertFailed("revert not possible")

    def __str__(self):
        return self.name


class TamperManager:
    """ TamperManager not only provides some automated ability to tamper with
    properties of the remote system, but also a tracker for all modifications 
    on the remote system with the ability to remove previous changes. Other modules
    can register system changes with `PtyHandler.tamper` in order to allow the 
    user to get a wholistic view of all modifications of the remote system, and
    attempt revert all modifications automatically. """

    def __init__(self):
        # List of tampers registered with this manager
        self.tampers: List[Tamper] = []

    def modified_file(
        self,
        path: str,
        original_content: Optional[bytes] = None,
        added_lines: Optional[List[str]] = None,
    ):
        """ Add a new modified file tamper """
        tamper = ModifiedFile(
            path, added_lines=added_lines, original_content=original_content
        )
        self.add(tamper)
        return tamper

    def created_file(self, path: str):
        """ Register a new added file on the remote system """
        tamper = CreatedFile(path)
        self.add(tamper)
        return tamper

    def add(self, tamper: Tamper):
        """ Register a custom tamper tracker """
        serialized = pickle.dumps(tamper)
        tracker = pwncat.db.Tamper(name=str(tamper), data=serialized)
        pwncat.victim.host.tampers.append(tracker)
        pwncat.victim.session.commit()

    def custom(self, name: str, revert: Optional[Callable] = None):
        tamper = LambdaTamper(name, revert)
        self.add(tamper)
        return tamper

    def __iter__(self) -> Iterator[Tamper]:
        for tracker in pwncat.victim.host.tampers:
            yield pickle.loads(tracker.data)

    def filter(self, base=Tamper):
        for tamper in self:
            if isinstance(tamper, base):
                yield tamper

    def __len__(self):
        return len(pwncat.victim.host.tampers)

    def __getitem__(self, item: int):
        if not isinstance(item, int):
            raise KeyError(f"{item}: not an integer")
        return pickle.loads(pwncat.victim.host.tampers[item].data)

    def remove(self, tamper: Tamper):
        """ Pop a tamper from the list of known tampers. This does not revert the tamper.
        It removes the tracking for this tamper. """

        tracker = (
            pwncat.victim.session.query(pwncat.db.Tamper)
            .filter_by(name=str(tamper))
            .first()
        )
        if tracker is not None:
            pwncat.victim.session.delete(tracker)
            pwncat.victim.session.commit()
