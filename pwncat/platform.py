#!/usr/bin/env python3
from enum import Flag, auto


class Platform(Flag):

    UNKNOWN = auto()
    WINDOWS = auto()
    BSD = auto()
    LINUX = auto()
    ANY = WINDOWS | BSD | LINUX
