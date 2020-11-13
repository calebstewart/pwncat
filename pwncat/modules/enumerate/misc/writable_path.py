#!/usr/bin/env python3
import os
import stat

import pwncat
from pwncat.util import Access
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import EnumerateModule, Schedule


class Module(EnumerateModule):
    """
    Locate any components of the current PATH that are writable
    by the current user.
    """

    PROVIDES = ["system.writable_path"]
    SCHEDULE = Schedule.PER_USER
    PLATFORM = [Linux]

    def enumerate(self, session):

        user = session.platform.current_user()

        for path in session.platform.getenv("PATH").split(":"):

            # Ignore empty components
            if path == "":
                continue

            # Find the first item up the path that exists
            path = session.platform.Path(path)
            while not path.exists():
                path = path.parent

            # See if we have write permission
            if path.is_dir() and path.writable():
                yield "misc.writable_path", str(path.resolve())
