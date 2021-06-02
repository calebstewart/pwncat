#!/usr/bin/env python3
import os
from io import IOBase, BytesIO
from pathlib import Path

import requests
from pwncat.modules import Bool, Argument, BaseModule, ModuleFailed
from pwncat.platform.windows import Windows


class PSModuleNotFoundError(ModuleFailed):
    def __init__(self, path):
        super().__init__(f"{path}: psmodule not found")


class Module(BaseModule):
    """
    Import a powershell module into the current powershell context.
    """

    ARGUMENTS = {
        "path": Argument(str, help="The module to load into the powershell context"),
        "force": Argument(
            Bool,
            help="Force module loading, even if it has been loaded before",
            default=False,
        ),
    }
    PLATFORM = [Windows]

    def __init__(self):
        self.imported_modules = []

    def resolve_psmodule(self, session: "pwncat.manager.Session", path: str):
        """ Resolve a module name into a file-like object """

        if path.startswith("http://") or path.startswith("https://"):
            # Load from a URL
            r = requests.get(path, stream=True)
            if r.status_code != 200:
                raise PSModuleNotFoundError(path)
            return path.split("/")[-1], BytesIO(r.content)

        orig_path = path
        path = Path(path)

        if path.is_file():
            # Load from absolute or CWD path
            return path.name, path.open("rb")
        elif (Path(session.config["psmodules"]) / path).is_file():
            # Load from local modules directory
            return path.name, (Path(session.config["psmodules"]) / path).open("rb")
        elif len(orig_path.lstrip("/").split("/")) > 2:
            # Load from githubusercontent.com ( path = "user/repo/path/to/file.ps1" )
            orig_path = orig_path.lstrip("/").split("/")
            orig_path.insert(2, "master")
            orig_path = "/".join(orig_path)
            url = f"https://raw.githubusercontent.com/{orig_path}"
            r = requests.get(url, stream=True)

            if r.status_code != 200:
                raise PSModuleNotFoundError(orig_path)

            return (path.name, BytesIO(r.content))
        else:
            raise PSModuleNotFoundError(orig_path)

    def run(self, session: "pwncat.manager.Session", path, force):

        name, filp = self.resolve_psmodule(session, path)

        if name in session.platform.psmodules and not force:
            return

        session.platform.powershell(filp)

        session.platform.psmodules.append(name)
