#!/usr/bin/env python3
from typing import IO, Callable, Optional

import rich.markup
from pwncat.db import Fact
from persistent.list import PersistentList
from pwncat.facts.tamper import *
from pwncat.facts.ability import *
from pwncat.facts.implant import *
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

    def description(self, session) -> str:
        return self.content


class EscalationReplace(Fact):
    """Performs escalation and transforms the current session into the context
    of the specified user.

    :param source: the name of the generating module
    :type source: str
    :param source_uid: the starting uid needed to use this escalation
    :param uid: the target uid for this escalation
    """

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["escalate.replace"], source=source)

        self.source_uid = source_uid
        self.uid = uid

    def escalate(
        self, session: "pwncat.manager.Session"
    ) -> Callable[["pwncat.manager.Session"], None]:
        """Execute the escalation optionally returning a new session

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :returns: Callable - A lambda taking the session and exiting the new shell
        """


class EscalationSpawn(Fact):
    """Performs escalation and spawns a new session in the context of the
    specified user. The execute method will return the new session.

    :param source: the name of the generating module
    :type source: str
    :param source_uid: the starting uid needed to use this escalation
    :param uid: the target uid for this escalation
    """

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["escalate.spawn"], source=source)

        self.source_uid = source_uid
        self.uid = uid

    def execute(self, session: "pwncat.manager.Session") -> "pwncat.manager.Session":
        """Spawn a new session under the context of a new user

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :returns: pwncat.manager.Session - a newly established session as the specified user
        """
