#!/usr/bin/env python3

import datetime

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class LocalTime(Fact):
    def __init__(self, source, localtime_string: str):
        super().__init__(source=source, types=["system.localtime"])

        self.localtime_string: str = localtime_string
        self.localtime: str = datetime.datetime.strptime(
            localtime_string, "%A, %B %d, %Y %I:%M:%S %p"
        )

    def title(self, session):
        return f"Local time is: {rich.markup.escape(self.localtime_string)}"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.localtime"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell('Get-Date -Format "F"')

            if not result:
                return

            if isinstance(result[0], list) and result:
                date_time = result[0]
            else:
                date_time = result[0]

        except PowershellError as exc:
            raise ModuleFailed("failed to retrieve local time") from exc

        yield LocalTime(self.name, date_time)
