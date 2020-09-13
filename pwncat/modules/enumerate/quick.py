#!/usr/bin/env python3

import pwncat
from pwncat.modules import BaseModule, Status, Argument


class Module(BaseModule):
    """ Perform a quick enumeration of common useful data """

    ARGUMENTS = {
        "output": Argument(
            str, default=None, help="Path a to file to write a markdown report"
        )
    }
    PLATFORM = pwncat.modules.Platform.ANY

    def run(self, output):
        return pwncat.modules.run(
            "enumerate.gather",
            progress=self.progress,
            types=["system.*", "software.sudo.*", "file.suid"],
            output=output,
        )
