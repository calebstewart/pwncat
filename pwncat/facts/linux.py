#!/usr/bin/env python3
from typing import Optional

from pwncat.facts import User, Group


class LinuxUser(User):
    """ Linux-specific user definition """

    def __init__(
        self,
        source,
        name,
        hash,
        uid,
        gid,
        comment,
        home,
        shell,
        password: Optional[str] = None,
    ):

        # Normally, the hash is only stored in /etc/shadow
        if hash == "x":
            hash = None

        super().__init__(source, name, uid, password=password, hash=hash)

        self.gid = gid
        self.comment = comment
        self.home = home
        self.shell = shell


class LinuxGroup(Group):
    """ Linux-specific group definition """

    def __init__(self, source, group_name, hash, gid, members, password=None):

        # We've never seen a group password hash, but those apparently exist????
        if hash == "x":
            hash = None

        super().__init__(source, group_name, gid, members)

        self.hash = hash
        self.password = password
