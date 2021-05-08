#!/usr/bin/env python3
from typing import Optional

import rich.markup
from persistent.list import PersistentList

from pwncat.db.fact import Fact


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

    def __str__(self):
        return f"""{rich.markup.escape(self.name)}, gid={self.id}, members={rich.markup.escape(",".join((m for m in self.members)))}"""


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
