#!/usr/bin/env python3
import datetime

from pwncat.db import Fact
from pwncat.modules import ModuleFailed


class Tamper(Fact):
    """A generic "tamper" or modification to the remote
    target. Tampers can sometimes be reverted automatically,
    but at worst are tracked through the enumeration system.

    :param source: a string describing the module or routine that generated the tamper
    :type source: str
    :param uid: the user ID needed to revert the tamper
    :param timestamp: the datetime that this change occurred
    :type timestamp: datetime.datetime
    """

    def __init__(self, source, uid, timestamp=None):
        super().__init__(source=source, types=["tamper"])

        self.uid = uid
        self.timestamp = timestamp if timestamp is not None else datetime.datetime.now()
        self.reverted = False

    @property
    def revertable(self):
        return False

    def revert(self, session: "pwncat.manager.Session"):
        raise ModuleFailed("not reverable")

    def _annotate_title(self, session, title):
        """Just a helper for annotating the description with details on
        the needed user and current revertability/state of the tamper."""

        if self.reverted:
            return f"{title} ([green]reverted[/green])"

        if self.data is not None:
            target_user = session.find_user(uid=self.uid)
            return f"{title} ([yellow]revertable[/yellow] as [blue]{target_user.name}[/blue])"

        return f"{title} ([red]non-revertable[/red]!)"


class ReplacedFile(Tamper):
    """Represents a file that was replaced on the remote host.
    This is a revertable tamper as long as the data was stored
    prior to replacement.

    :param source: generating module or routine
    :type source: str
    :param uid: UID needed to revert
    :param path: path to replaced file
    :type path: str or Path-like
    :param data: the original data in the file
    :type data: str, bytes or None
    :param timestamp: the datetime that this change occurred
    :type timestamp: datetime.datetime
    """

    def __init__(self, source, uid, path, data, timestamp=None):
        super().__init__(source, uid, timestamp=timestamp)

        if isinstance(data, str):
            data = data.encode("utf-8")

        self.path = str(path)
        self.data = data

    def revert(self, session: "pwncat.manager.Session"):

        if self.data is None:
            raise ModuleFailed("original data not preserved")

        current_uid = session.platform.getuid()
        if current_uid != self.uid:
            target_user = session.find_user(uid=self.uid)
            raise ModuleFailed(f"incorrect permission (need: {target_user.name})")

        # Re-write the original data to the file
        with session.platform.open(self.path, "wb") as filp:
            filp.write(self.data)

        self.reverted = True

    @property
    def revertable(self):
        if self.data is None:
            return False
        return True

    def title(self, session: "pwncat.manager.Session"):

        return self._annotate_title(
            session, f"replace content of [cyan]{self.path}[/cyan]"
        )


class CreatedFile(Tamper):
    """ Tracks a new file created on the target """

    def __init__(self, source, uid, path, timestamp=None):
        super().__init__(source, uid, timestamp=timestamp)

        self.path = path

    @property
    def revertable(self):
        return True

    def revert(self, session: "pwncat.manager.Session"):

        try:
            session.platform.Path(self.path).unlink()
        except PermissionError:
            raise ModuleFailed("permission error")

        self.reverted = True

    def title(self, session: "pwncat.manager.Session"):

        return self._annotate_title(
            session, f"created file at [cyan]{self.path}[/cyan]"
        )


class CreatedDirectory(Tamper):
    """Tracks a new directory created on the target. The entire
    directory will be deleted upon reversion"""

    def __init__(self, source, uid, path, timestamp=None):
        super().__init__(source, uid, timestamp=timestamp)

        self.path = path

    @property
    def revertable(self):
        return True

    def revert(self, session: "pwncat.manager.Session"):

        try:
            session.platform.Path(self.path).rmdir()
        except PermissionError:
            raise ModuleFailed("permission error")

        self.reverted = True

    def title(self, session: "pwncat.manager.Session"):
        return self._annotate_title(
            session, f"created directory at [cyan]{self.path}[cyan]"
        )
