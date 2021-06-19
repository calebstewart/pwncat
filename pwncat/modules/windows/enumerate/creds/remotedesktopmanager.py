#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class RemoteDesktopManagerCreds(Fact):
    def __init__(self, source, path: str):
        super().__init__(source=source, types=["creds.remotedesktopmanager"])

        self.path: str = path

    def title(self, session):
        if not self.path:
            return "[red]Remote Desktop Manager credentials file not present[/red]"
        else:
            return f"[green]Remote Desktop Manager credentials file: {rich.markup.escape(self.path)}[/green]"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["creds.remotedesktopmanager"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            result = session.platform.powershell(
                '(Get-ChildItem "$env:APPDATA\\Local\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings").FullName'
            )

            if not result:
                yield RemoteDesktopManagerCreds(self.name, "")

            if isinstance(result[0], list) and result:
                path = "\n".join(result[0])
            else:
                path = result[0]

                yield RemoteDesktopManagerCreds(self.name, path)

        except PowershellError as exc:
            if "does not exist" in exc.message:
                yield RemoteDesktopManagerCreds(self.name, path="")
            else:
                raise ModuleFailed(
                    "failed to retrieve check for remote desktop creds"
                ) from exc
