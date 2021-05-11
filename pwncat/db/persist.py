#!/usr/bin/env python3

from typing import Optional

import persistent


class Persistence(persistent.Persistent):
    """
    Stores an abstract understanding of persistence method installed on a
    target.
    """

    def __init__(self, method, user):

        # The type of persistence
        self.method: Optional[str] = method
        # The user this persistence was applied as
        # (ignored for system persistence)
        self.user: Optional[str] = user

        # The original SQLAlchemy-style code held a property, "args",
        # which was a pickle object contained the custom arguments passed to
        # the persistence module. It **will** include the `user` argument.
        # We may re-implement that as a subclass.
