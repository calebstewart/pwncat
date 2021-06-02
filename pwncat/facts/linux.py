"""
Linux specific facts which are used in multiple places throughout
the framework.
"""
from typing import List, Optional

from pwncat.facts import User, Group


class LinuxUser(User):
    """Linux-specific user definition. This augments the base
    :class:`pwncat.facts.User` class to hold data specific to
    Linux.

    :param source: the generating module name
    :type source: str
    :param name: name of the user
    :type name: str
    :param hash: password hash if known
    :type hash: Optional[str]
    :param uid: user identifier
    :type uid: int
    :param gid: group identifier
    :type gid: int
    :param comment: user comment (sometimes called full name)
    :type comment: str
    :param home: the path to the users home directory
    :type home: str
    :param shell: path to the users login shell
    :type shell: str
    :param password: the users password, if known
    :type password: str
    """

    def __init__(
        self,
        source: str,
        name: str,
        hash: Optional[str],
        uid: int,
        gid: int,
        comment: str,
        home: str,
        shell: str,
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
    """Linux-specific group definition this augments the base
    :class:`pwncat.facts.Group` class to hold data specific to
    Linux.

    :param source: the generating module name
    :type source: str
    :param group_name: name of the user
    :type group_name: str
    :param hash: password hash if known
    :type hash: Optional[str]
    :param gid: group identifier
    :type gid: int
    :param members: list of user identifiers who are members of this group
    :type members: List[int]
    :param password: the users password, if known
    :type password: str
    """

    def __init__(
        self,
        source: str,
        group_name: str,
        hash: Optional[str],
        gid: int,
        members: List[int],
        password: Optional[str] = None,
    ):

        # We've never seen a group password hash, but those apparently exist????
        if hash == "x":
            hash = None

        super().__init__(source, group_name, gid, members)

        self.hash = hash
        self.password = password
