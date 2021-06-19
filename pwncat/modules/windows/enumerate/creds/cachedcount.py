#!/usr/bin/env python3

from typing import Any

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class CachedCredsCount(Fact):
    def __init__(self, source, count: Any):
        super().__init__(source=source, types=["creds.cachedcount"])

        self.count = count

    def title(self, session):
        if self.count:
            return f"'CachedLogonsCount' = {rich.markup.escape(self.count)}, you need SYSTEM rights to extract them"
        else:
            return f"'CachedLogonsCount' = 0"


class Module(EnumerateModule):
    """Enumerate the number of cached credentials on the target"""

    PROVIDES = ["creds.cachedcount"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                "Get-ItemPropertyValue 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -Name 'CachedLogonsCount'"
            )

            if not result:
                yield CachedCredsCount(self.name, count=0)

            if isinstance(result[0], list) and result:
                count = result[0]
            else:
                count = result[0]

            yield CachedCredsCount(self.name, count)

        except PowershellError as exc:
            if "does not exist" in exc.message:
                yield CachedCredsCount(self.name, count=0)
            else:
                raise ModuleFailed("failed to retrieve wdigest settings") from exc
