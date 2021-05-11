#!/usr/bin/env python3

from typing import Optional

import persistent


class Tamper(persistent.Persistent):
    """
    Stores a record of changes on the target (i.e., things that have been
    tampered with)
    """

    def __init__(self, name, data):

        # The name of this tamper method (what was done on the target)
        self.name: Optional[str] = name
        # The process outlined in this tamper method
        self.data: Optional[bytes] = data
