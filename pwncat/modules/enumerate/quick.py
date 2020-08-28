#!/usr/bin/env python3

import pwncat.modules
from pwncat.modules import BaseModule, Status, Argument


class Module(BaseModule):
    """ Perform a quick enumeration of common useful data """

    ARGUMENTS = {"output": Argument(str, default=None)}

    def run(self, output):
        return next(pwncat.modules.match("enumerate.report")).run(
            types=["file.suid", "file.caps"], output=output
        )
