#!/usr/bin/env python3

import persistent
from typing import Optional


class Fact(persistent.Persistent):
    """Store enumerated facts. The pwncat.enumerate.Fact objects are pickled and
    stored in the "data" column. The enumerator is arbitrary, but allows for
    organizations based on the source enumerator."""

    def __init__(self, arg_type, source):

        # The type of fact (e.g.., "system.user")
        self.type: Optional[str] = arg_type
        # The original procedure that found this fact
        self.source: Optional[str] = source

        # The original SQLAlchemy-style code held a property, "data",
        # which was a pickle object. We will re-implement that as a subclass
        # but that may need to include the class properties used previously.

    @property
    def category(self) -> str:
        return f"{self.type}"
