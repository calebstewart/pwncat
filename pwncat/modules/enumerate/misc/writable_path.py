#!/usr/bin/env python3
import os

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

    def enumerate(self):

        for path in pwncat.victim.getenv("PATH").split(":"):
            access = pwncat.victim.access(path)
            if (Access.DIRECTORY | Access.WRITE) in access:
                yield "misc.writable_path", path
            elif (
                Access.EXISTS not in access
                and (Access.PARENT_EXIST | Access.PARENT_WRITE) in access
            ):
                yield "misc.writable_path", path
            elif access == Access.NONE:
                # This means the parent directory doesn't exist. Check up the chain to see if
                # We can create this chain of directories
                dirpath = os.path.dirname(path)
                access = pwncat.victim.access(dirpath)
                # Find the first item that either exists or it's parent does
                while access == Access.NONE:
                    dirpath = os.path.dirname(dirpath)
                    access = pwncat.victim.access(dirpath)
                # This item exists. Is it a directory and can we write to it?
                if (Access.DIRECTORY | Access.WRITE) in access:
                    yield "misc.writable_path", path
                elif (
                    Access.PARENT_EXIST | Access.PARENT_WRITE
                ) in access and Access.EXISTS not in access:
                    yield "misc.writable_path", path
