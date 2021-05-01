#!/usr/bin/env python3

import persistent
import persistent.list
from typing import Optional


class Group(persistent.Persistent):
    """
    Stores a record of changes on the target (i.e., things that have been
    tampered with)
    """

    def __init__(self, name, members):

        self.name: Optional[str] = name
        self.members: persistent.list.PersistentList = persistent.list.PersistentList()

    def __repr__(self):
        return f"""Group(gid={self.id}, name={repr(self.name)}), members={repr(",".join(m.name for m in self.members))})"""


class User(persistent.Persistent):
    def __init__(self, name, gid, fullname, homedir, password, hash, shell, groups):

        self.name: Optional[str] = name
        self.gid: Optional[int] = gid
        self.fullname: Optional[str] = fullname
        self.homedir: Optional[str] = homedir
        self.password: Optional[str] = password
        self.hash: Optional[str] = hash
        self.shell: Optional[str] = shell
        self.groups: persistent.list.PersistentList = persistent.list.PersistentList(
            groups
        )

    def __repr__(self):
        return f"""User(uid={self.id}, gid={self.gid}, name={repr(self.name)})"""
