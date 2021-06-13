"""
Tampers are modifications which we knowingly made to the target host.
pwncat tracks tampers wherever it can in order to warn the user that
modifications have been made, and in some cases provide the ability
to revert those modifications. This is not foolproof, but provides
some ability to track your changes when on target.
"""
import datetime
from typing import Union, Optional

import pwncat
from pwncat.db import Fact
from pwncat.modules import ModuleFailed


class Tamper(Fact):
    """A generic "tamper" or modification to the remote
    target. Tampers can sometimes be reverted automatically,
    but at worst are tracked through the enumeration system.

    :param source: a string describing the module or routine that generated the tamper
    :type source: str
    :param uid: the user ID needed to revert the tamper
    :type uid: Union[int, str]
    :param timestamp: the datetime that this change occurred
    :type timestamp: Optional[datetime.datetime]
    """

    def __init__(
        self,
        source: str,
        uid: Union[int, str],
        timestamp: Optional[datetime.datetime] = None,
    ):
        super().__init__(source=source, types=["tamper"])

        self.uid = uid
        self.timestamp = timestamp if timestamp is not None else datetime.datetime.now()
        self.reverted = False

    @property
    def revertable(self):
        """ Test if this tamper is currently revertable """
        return False

    def revert(self, session: "pwncat.manager.Session"):
        """Attempt to revert the tamper through the given session.

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        """
        raise ModuleFailed("not reverable")

    def _annotate_title(self, session, title):
        """Just a helper for annotating the description with details on
        the needed user and current revertability/state of the tamper."""

        if self.reverted:
            return f"{title} ([green]reverted[/green])"

        if self.revertable:
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
    :type uid: Union[int, str]
    :param path: path to replaced file
    :type path: str
    :param data: the original data in the file
    :type data: Optional[Union[str, bytes]]
    :param timestamp: the datetime that this change occurred
    :type timestamp: Optional[datetime.datetime]
    """

    def __init__(
        self,
        source: str,
        uid: Union[int, str],
        path: str,
        data: Optional[Union[str, bytes]],
        timestamp: Optional[datetime.datetime] = None,
    ):
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
    """Tracks a new file created on the target. This is normally
    revertable as we just need to delete the file.

    :param source: generating module or routine
    :type source: str
    :param uid: UID needed to revert
    :type uid: Union[int, str]
    :param path: path to replaced file
    :type path: str
    :param timestamp: the datetime that this change occurred
    :type timestamp: Optional[datetime.datetime]
    """

    def __init__(
        self,
        source: str,
        uid: Union[int, str],
        path: str,
        timestamp: Optional[datetime.datetime] = None,
    ):
        super().__init__(source, uid, timestamp=timestamp)

        self.path = path

    @property
    def revertable(self):
        return True

    def revert(self, session: "pwncat.manager.Session"):

        try:
            session.platform.Path(self.path).unlink()
        except FileNotFoundError:
            pass
        except PermissionError:
            raise ModuleFailed("permission error")

        self.reverted = True

    def title(self, session: "pwncat.manager.Session"):

        return self._annotate_title(
            session, f"created file at [cyan]{self.path}[/cyan]"
        )


class CreatedDirectory(Tamper):
    """Tracks a new directory created on the target. The entire
    directory will be deleted upon revert.

    :param source: generating module or routine
    :type source: str
    :param uid: UID needed to revert
    :type uid: Union[int, str]
    :param path: path to replaced file
    :type path: str
    :param timestamp: the datetime that this change occurred
    :type timestamp: Optional[datetime.datetime]
    """

    def __init__(
        self,
        source: str,
        uid: Union[int, str],
        path: str,
        timestamp: Optional[datetime.datetime] = None,
    ):
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
