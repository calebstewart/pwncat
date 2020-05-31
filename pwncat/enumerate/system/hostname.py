#!/usr/bin/env python3
from typing import Generator

import pwncat
from pwncat.enumerate import FactData

name = "pwncat.enumerate.system"
provides = "system.hostname"
per_user = False


def enumerate() -> Generator[FactData, None, None]:
    """
    Enumerate system hostname facts
    :return: A generator of hostname facts
    """

    try:
        hostname = pwncat.victim.env(["hostname", "-f"]).decode("utf-8").strip()
        yield hostname
        return
    except FileNotFoundError:
        pass

    try:
        hostname = pwncat.victim.env(["hostnamectl"]).decode("utf-8").strip()
        hostname = hostname.replace("\r\n", "\n").split("\n")
        for name in hostname:
            if "static hostname" in name.lower():
                hostname = name.split(": ")[1]
                yield hostname
                return
    except (FileNotFoundError, IndexError):
        pass

    return
