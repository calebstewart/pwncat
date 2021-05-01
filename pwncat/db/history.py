#!/usr/bin/env python3

import persistent
from typing import Optional


class History(persistent.Persistent):
    """Store history of ran commands on the target."""

    def __init__(self, command):

        # The command ran on the target (e.g., "whoami")
        self.command: Optional[str] = command
