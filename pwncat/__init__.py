#!/usr/bin/env python3
from typing import Optional

import pwncat.db
import pwncat.modules
import pwncat.platform
import pwncat.commands
import pwncat.config
import pwncat.file
import pwncat.remote
import pwncat.tamper
import pwncat.util

victim: Optional["pwncat.remote.Victim"] = None
