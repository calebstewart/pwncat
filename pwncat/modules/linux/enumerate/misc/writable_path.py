#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class WritablePath(Fact):
    def __init__(self, source, path):
        super().__init__(source=source, types=["misc.writable_path"])

        self.path: str = path

    def title(self, session):
        return f"""{rich.markup.escape(self.path)}"""


class Module(EnumerateModule):
    """
    Locate any components of the current PATH that are writable
    by the current user.
    """

    PROVIDES = ["system.writable_path"]
    SCHEDULE = Schedule.PER_USER
    PLATFORM = [Linux]

    def enumerate(self, session):

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
                yield WritablePath(self.name, str(path.resolve()))
