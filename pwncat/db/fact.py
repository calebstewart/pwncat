#!/usr/bin/env python3
from typing import Optional

import persistent
from pwncat.modules import Result
from persistent.list import PersistentList


class Fact(Result, persistent.Persistent):
    """Abstract enumerated facts about an enumerated target. Individual
    enumeration modules will create subclasses containing the data for
    the fact. A generic fact is guaranteed to have a list of types, a
    module source, a __repr__ implementation, a __str__ implementation.

    By default, a category property is defined which is the first type
    in the list of types. This can be overloaded if needed, and is used
    when formatted and displaying enumeration results.

    Lastly, if the description property is not None, it indicates that
    the fact has a "long form" description as opposed to a single-line
    content. This only effects the way reports are generated.
    """

    def __init__(self, types, source):
        super().__init__()

        if not isinstance(types, PersistentList):
            types = PersistentList(types)

        # The type of fact (e.g.., "system.user")
        self.types: PersistentList = types
        # The original procedure that found this fact
        self.source: str = source

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
