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


class InstalledProgramData(Fact):
    def __init__(self, source, path: bool):
        super().__init__(source=source, types=["system.programs"])

        self.path: bool = path

    def title(self, session):
        return f"{rich.markup.escape(repr(self.path))}"


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["system.programs"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        try:
            program_files = session.platform.powershell(
                f'Get-ChildItem "C:\\Program Files","C:\\Program Files (x86)" -ErrorAction SilentlyContinue | Select Fullname'
            )[0]

            if not isinstance(program_files, list):
                program_files = [program_files]

            for path in program_files:
                yield InstalledProgramData(self.name, path["FullName"])

        except (PowershellError, IndexError) as exc:
            raise ModuleFailed(
                f"failed to list program file directories: {exc}"
            ) from exc
