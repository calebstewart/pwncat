#!/usr/bin/env python3

from typing import Any, Dict, List

import rich.markup

import pwncat
from pwncat import util
from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform import PlatformError
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


class LSAProtectionData(Fact):
    def __init__(self, source, active: bool):
        super().__init__(source=source, types=["protections.lsa"])

        self.active: bool = active

    def title(self, session):
        out = "LSA Protection is "
        out += (
            "[bold red]active[/bold red]"
            if self.active
            else "[bold green]inactive[/bold green]"
        )
        return out

    def description(self, session):
        return None


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["protections.lsa"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        registry_value = "RunAsPPL"
        registry_key = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\LSA"

        try:
            result = session.platform.powershell(
                f"Get-ItemPropertyValue {registry_key} -Name {registry_value}"
            )

            if not result:
                raise ModuleFailed(
                    f"failed to retrieve registry value {registry_value}"
                )

            status = bool(result[0])

        except PowershellError as exc:
            if "does not exist" in exc.message:
                status = bool(0)  # default
            else:
                raise ModuleFailed(
                    f"could not retrieve registry value {registry_value}: {exc}"
                ) from exc

            yield LSAProtectionData(self.name, status)
