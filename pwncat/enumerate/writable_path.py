#!/usr/bin/env python3
"""
Enumerate directories in your PATH which are writable. All paths which are generated
from this enumerator are either directly writable, or do not exist but are under a
path which you have write access to. If the directory returned from this enumerator
does not exist, a call to `mkdir -p {directory}` should succeed.
"""
import os
from typing import Generator

from pwncat.enumerate import FactData
import pwncat
from pwncat.util import Access

name = "pwncat.enumerate.writable_path"
provides = "writable_path"
per_user = False
always_run = False


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate directories in our PATH which are writable
    :return:
    """

    for path in pwncat.victim.getenv("PATH").split(":"):
        access = pwncat.victim.access(path)
        if (Access.DIRECTORY | Access.WRITE) in access:
            yield path
        elif (
            Access.EXISTS not in access
            and (Access.PARENT_EXIST | Access.PARENT_WRITE) in access
        ):
            yield path
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
                yield path
            elif (
                Access.PARENT_EXIST | Access.PARENT_WRITE
            ) in access and Access.EXISTS not in access:
                yield path
