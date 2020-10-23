#!/usr/bin/env python3
import random
import time

import pwncat
from pwncat.modules import BaseModule, List, Argument, Result


class Module(BaseModule):
    """  """

    ARGUMENTS = {"arg1": Argument(type=int)}
    PLATFORM = None

    def run(self, arg1):
        values = [random.randint(1, 100) for _ in range(arg1)]

        for i in values:
            yield i
            time.sleep(1)
