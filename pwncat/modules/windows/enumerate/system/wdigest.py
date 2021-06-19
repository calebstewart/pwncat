#!/usr/bin/env python3

from typing import Any

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class WDigest(Fact):
    def __init__(self, source, configured: Any):
        super().__init__(source=source, types=["system.wdigest"])

        self.configured = configured

    def title(self, session):
        if self.configured:
            return f"'UseLogonCredential' wdigest is 1, [bold green]there are plaintext credentials in memory![/bold green]"
        else:
            return f"'UseLogonCredential' wdigest is not configured"


class Module(EnumerateModule):
    """Enumerate the current WDigest settings on the target"""

    PROVIDES = ["system.wdigest"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                "Get-ItemPropertyValue 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\' -Name 'UseLogonCredential'"
            )

            if not result:
                yield WDigest(self.name, configured=False)

            if isinstance(result[0], list) and result:
                configured = result[0]
            else:
                configured = result[0]

            yield WDigest(self.name, configured)

        except PowershellError as exc:
            if "does not exist" in exc.message:
                yield WDigest(self.name, configured=False)
            else:
                raise ModuleFailed("failed to retrieve wdigest settings") from exc
