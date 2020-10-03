#!/usr/bin/env python3
from enum import Flag, auto


class Platform(Flag):

    UNKNOWN = auto()
    WINDOWS = auto()
    BSD = auto()
    LINUX = auto()
    # This deserves some explanation.
    # This indicates that component of pwncat does not need an
    # actively connected host to be utilized. When used as a
    # module platform, it indicates that the module itself
    # only deals with the database or internal pwncat features.
    # and is allowed to run prior to a victim being connected.
    NO_HOST = auto()
    ANY = WINDOWS | BSD | LINUX
