#!/usr/bin/env python3
from typing import IO, Callable, Optional

import rich.markup
from persistent.list import PersistentList

from pwncat.db import Fact
from pwncat.facts.ability import *
from pwncat.facts.escalate import *


class Group(Fact):
    """Basic representation of a user group on the target system. Individual
    platform enumeration modules may subclass this to implement other user
    properties as needed for their platform."""

    def __init__(self, source: str, name: str, gid, members):
        super().__init__(["group"], source)

        self.name: str = name
        self.id = gid
        self.members: PersistentList = PersistentList(members)

    def __repr__(self):
        return f"""Group(gid={self.id}, name={repr(self.name)}, members={repr(self.members)})"""


class User(Fact):
    """Basic representation of a user on the target system. Individual platform
    enumeration modules may subclass this to implement other user properties as
    needed for their platform."""

    def __init__(
        self,
        source: str,
        name,
        uid,
        password: Optional[str] = None,
        hash: Optional[str] = None,
    ):
        super().__init__(["user"], source)

        self.name: str = name
        self.id = uid
        self.password: Optional[str] = None
        self.hash: Optional[str] = None

    def __repr__(self):
        if self.password is None and self.hash is None:
            return f"""User(uid={self.id}, name={repr(self.name)})"""
        elif self.password is not None:
            return f"""User(uid={repr(self.id)}, name={repr(self.name)}, password={repr(self.password)})"""
        else:
            return f"""User(uid={repr(self.id)}, name={repr(self.name)}, hash={repr(self.hash)})"""


class PotentialPassword(Fact):
    """A password possible extracted from a remote file
    `filepath` and `lineno` may be None signifying this
    password did not come from a file directly.
    """

    def __init__(self, source, password, filepath, lineno, uid):
        super().__init__(source=source, types=["creds.password"])

        self.password: str = password
        self.filepath: str = filepath
        self.lineno: int = lineno
        self.uid: int = uid  # We are Linux-specific here so this can be a literal UID

    def title(self, session):
        if self.password is not None:
            result = f"Potential Password [cyan]{rich.markup.escape(repr(self.password))}[/cyan]"
            if self.uid is not None:
                result += f" for [blue]{rich.markup.escape(session.find_user(uid = self.uid).name)}[/blue]"
            if self.filepath is not None:
                result += f" ({rich.markup.escape(self.filepath)}:{self.lineno})"
        else:
            result = f"Potential Password at [cyan]{rich.markup.escape(self.filepath)}[/cyan]:{self.lineno}"

        return result


class PrivateKey(Fact):
    """A private key found on the remote file system or known
    to be applicable to this system in some way."""

    def __init__(self, source, path, uid, content, encrypted):
        super().__init__(source=source, types=["creds.private_key"])

        self.uid: int = uid
        """ The uid we believe the private key belongs to """
        self.path: str = path
        """ The path to the private key on the remote host """
        self.content: str = content
        """ The actual content of the private key """
        self.encrypted: bool = encrypted
        """ Is this private key encrypted? """

    def __str__(self):
        if self.uid == 0:
            color = "red"
        else:
            color = "green"
        return f"Potential private key for [{color}]{self.uid}[/{color}] at [cyan]{rich.markup.escape(self.path)}[/cyan]"

    @property
    def description(self) -> str:
        return self.content


class FileReadAbility(Fact):
    """Ability to read a file as a different user"""

    def __init__(self, source, uid):
        super().__init__(types=["ability.file.read"], source=source)

        self.uid = uid

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ) -> IO:
        """Open a file for reading. This method mimics the builtin open
        function, and returns a file-like object for reading."""


class FileWriteAbility(Fact):
    """Ability to write a file as a different user"""

    def __init__(self, source, uid):
        super().__init__(types=["ability.file.write"], source=source)

        self.uid = uid

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ) -> IO:
        """Open a file for writing. This method mimics the builtin open
        function and returns a file-like object for writing."""


class ExecuteAbility(Fact):
    """Ability to execute a binary as a different user"""

    def __init__(self, source, uid):
        super().__init__(types=["ability.execute"], source=source)

        self.uid = uid

    def shell(
        self, session: "pwncat.manager.Session"
    ) -> Callable[["pwncat.manager.Session"], None]:
        """Replace the current shell with a new shell as the identified user

        :param session: the session to operate on
        :type session: pwncat.manager.Session
        :returns: Callable - A lambda taking the session and exiting the new shell
        """


class SpawnAbility(Fact):
    """Ability to spawn a new process as a different user without communications"""

    def __init__(self, source, uid):
        super().__init__(types=["ability.spawn"], source=source)

    def execute(self, session: "pwncat.manager.Session", command: str):
        """Utilize this ability to execute a command as a different user

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :param command: a command to execute
        :type command: str
        """


class EscalationReplace(Fact):
    """Performs escalation and transforms the current session into the context
    of the specified user."""

    def __init__(self, source, uid):
        super().__init__(types=["escalate.replace"], source=source)

        self.uid = uid

    def execute(
        self, session: "pwncat.manager.Session"
    ) -> Callable[["pwncat.manager.Session"], None]:
        """Execute the escalation optionally returning a new session

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :returns: Callable - A lambda taking the session and exiting the new shell
        """


class EscalationSpawn(Fact):
    """Performs escalation and spawns a new session in the context of the
    specified user. The execute method will return the new session."""

    def __init__(self, source, uid):
        super().__init__(types=["escalate.spawn"], source=source)

        self.uid = uid

    def execute(self, session: "pwncat.manager.Session") -> "pwncat.manager.Session":
        """Spawn a new session under the context of a new user

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :returns: pwncat.manager.Session - a newly established session as the specified user
        """
