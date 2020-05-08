#!/usr/bin/env python3
from typing import Type, List

from pwncat.privesc.base import Privesc, PrivescError
from pwncat.privesc.setuid import SetuidPrivesc

all_privescs = [SetuidPrivesc]
privescs = [SetuidPrivesc]


def get_names() -> List[str]:
    """ get the names of all privescs """
    return [d.NAME for d in all_privescs]


def find(pty: "pwncat.pty.PtyHandler", hint: str = None) -> Type[Privesc]:
    """ Locate an applicable privesc """

    if hint is not None:
        # Try to return the requested privesc
        for d in all_privescs:
            if d.NAME != hint:
                continue
            d.check(pty)
            return d

        raise PrivescError(f"{hint}: no such privesc")

    for d in privescs:
        try:
            d.check(pty)
            return d
        except PrivescError:
            continue
    else:
        raise PrivescError("no acceptable privescs found")
