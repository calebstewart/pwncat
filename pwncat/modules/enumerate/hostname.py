#!/usr/bin/env python3
from typing import List
import dataclasses

import pwncat
from pwncat.platform import Platform
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


class Module(EnumerateModule):
    """
    Enumerate system hostname facts
    :return: A generator of hostname facts
    """

    PROVIDES = ["network.hostname"]
    PLATFORM = Platform.LINUX

    def enumerate(self):

        try:
            hostname = pwncat.victim.env(["hostname", "-f"]).decode("utf-8").strip()
            yield "network.hostname", hostname
            return
        except FileNotFoundError:
            pass

        try:
            hostname = pwncat.victim.env(["hostnamectl"]).decode("utf-8").strip()
            hostname = hostname.replace("\r\n", "\n").split("\n")
            for name in hostname:
                if "static hostname" in name.lower():
                    hostname = name.split(": ")[1]
                    yield "network.hostname", hostname
                    return
        except (FileNotFoundError, IndexError):
            pass

        return
