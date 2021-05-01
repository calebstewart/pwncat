#!/usr/bin/env python3

import persistent
from typing import Optional


class SUID(persistent.Persistent):
    """
    Stores a record of SUID binaries discovered on the target.
    """

    def __init__(self, path, user):

        # Path to this SUID binary
        self.path: Optional[str] = path

        # The original SQLAlchemy-style code held a property, "owner_id",
        # which maintained the uid corresponding to the user owning this suid
        # file. This may or may not be needed?
