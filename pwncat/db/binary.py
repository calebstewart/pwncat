#!/usr/bin/env python3

from typing import Optional

import persistent


class Binary(persistent.Persistent):
    """
    Stores an understanding of a binary on the target.
    """

    def __init__(self, name, path):

        # Name of the binary (parameter to which)
        self.name: Optional[str] = name
        # The path to the binary on the remote host
        self.path: Optional[str] = path
