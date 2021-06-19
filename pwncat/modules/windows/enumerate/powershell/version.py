#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class PowerShellVersion(Fact):
    def __init__(self, source, version_numbers: dict):
        super().__init__(source=source, types=["powershell.version"])

        self.version_numbers: dict = version_numbers
        self.major = version_numbers["Major"]
        self.minor = version_numbers["Minor"]
        self.build = version_numbers["Build"]
        self.revision = version_numbers["Revision"]
        self.version: str = ".".join(
            [
                rich.markup.escape(str(number))
                for number in [self.major, self.minor, self.build, self.revision]
            ]
        )

    def title(self, session):
        return f"Current PowerShell version: {self.version}"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["powershell.version"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell("$PSVersionTable.PSVersion")

            if not result:
                return

            if isinstance(result[0], list) and result:
                version_numbers = "\n".join(result[0])
            else:
                version_numbers = result[0]

        except PowershellError as exc:
            raise ModuleFailed("failed to retrieve powershell version") from exc

        yield PowerShellVersion(self.name, version_numbers)
