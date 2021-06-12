"""
This package defines all database objects. pwncat internally uses
the ZODB database, which stores data as persistent Python objects.
Each class defined under this package is a persistent Python
class which is stored verabtim in the database. For documentation
on how to create persistent classes, please see the ZODB
documentation.
"""
from typing import Optional

import persistent
from persistent.list import PersistentList

from pwncat.modules import Result


class Binary(persistent.Persistent):
    """Store the name and path to binaries. This serves as the cache for
    :func:`pwncat.platform.Platform.which`."""

    def __init__(self, name, path):

        # Name of the binary (parameter to which)
        self.name: Optional[str] = name
        # The path to the binary on the remote host
        self.path: Optional[str] = path


class Fact(Result, persistent.Persistent):
    """Abstract enumerated fact about an enumerated target. Individual
    enumeration modules will create subclasses containing the data for
    the fact. All facts are also implementations of :class:`Result`
    which allows them to be generically displayed to the terminal.
    """

    def __init__(self, types, source):
        super().__init__()

        if not isinstance(types, PersistentList):
            types = PersistentList(types)

        # The type of fact (e.g.., "system.user")
        self.types: PersistentList = types
        # The original procedure that found this fact
        self.source: str = source
        self.hidden: bool = False

    def __eq__(self, o):
        """This is probably a horrible idea.

        NOTE: This is called for every comparison... the `in` operator
        wasn't working for persistent lists, so we need this to verify
        uniqueness of facts in the database.
        """

        for name, value in self.__dict__.items():
            if name.startswith("_"):
                continue
            if not hasattr(o, name) or getattr(o, name) != value:
                return False

        return True

    def category(self, session) -> str:
        return f"{self.types[0]} facts"

    @property
    def type(self):
        return self.types[0]
