from typing import List, Type
from time import sleep
from pwncat.subprocess import DEVNULL, CalledProcessError

import pwncat
from pwncat.modules import BaseModule, Status, Argument
from pwncat.platform import Platform, Windows, Linux
from pwncat.util import random_string


def stream_process(process):
    go = process.poll() is None
    for line in process.stdout:
        print(line.rstrip().decode())
    return go


def stream(process):
    while stream_process(process):
        sleep(0.1)


def mktemp(session: "pwncat.manager.Session", mode: str = "wb", suffix: str = ""):
    platform = session.platform

    if not "." in suffix:
        suffix = "." + suffix

    if type(platform) == Windows:
        path = platform.Path(platform.powershell("$_ = [System.IO.Path]::GetTempPath() ; $_")[0])

        while True:
            name = random_string(length=8) + suffix
            try:
                platform.new_item(ItemType="File", Path=str(path / name))
                break
            except FileExistsError:
                continue

        return (path / name).open(mode=mode)

    elif type(platform) == Linux:
        path = ""

        # Find a suitable temporary directory
        tempdir = platform.Path("/dev/shm")
        if not tempdir.is_dir():
            tempdir = platform.Path("/tmp")
        if not tempdir.is_dir():
            raise FileNotFoundError("no temporary directories!")

        # This is safer, and costs less, but `mktemp` may not exist
        mktemp = platform.which("mktemp")
        if mktemp is not None:
            try:
                result = platform.run(
                    [mktemp, "-p", str(tempdir), "--suffix", suffix, "X" * 8],
                    stderr=DEVNULL,
                    capture_output=True,
                    text=True,
                )
                path = platform.Path(result.stdout.rstrip("\n"))
            except CalledProcessError as exc:
                raise PermissionError(str(exc))

        if mktemp is None and not path:
            path = tempdir / (random_string(8) + suffix)
            while path.exists():
                path = tempdir / (random_string(8) + suffix)

        return platform.open(str(path), mode)


class PeassModule(BaseModule):

    PLATFORM: List[Type[Platform]] = []

    ARGUMENTS = {
        "source": Argument(str,
                           default="",
                           help="source of Peass-ng file if it exist (default: download the file directly to the target)"
                           )
    }

    def run(self, session: "pwncat.manager.Session", source: str):

        self.enumerate(session, source)
        yield Status(session)

    def enumerate(self, session: "pwncat.manager.Session", source) -> None:
        None
