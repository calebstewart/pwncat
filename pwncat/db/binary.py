#!/usr/bin/env python3

import persistent
from typing import Optional


class Binary(persistent.Persistent):
    """
    Stores an understanding of a binary on the target.
    """

    def __init__(self, name, path):

        # Name of the binary (parameter to which)
        self.name: Optional[str] = name
        # The path to the binary on the remote host
        self.path: Optional[str] = path
