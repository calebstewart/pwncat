#!/usr/bin/env python3
from typing import Optional

from .config import Config

victim: Optional["pwncat.remote.Victim"] = None

config: Config = Config()
