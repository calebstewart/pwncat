from typing import List, Type
from time import sleep, gmtime as time_gmtime
from pwncat.subprocess import DEVNULL, CalledProcessError

import pwncat
from pwncat.modules import BaseModule, Status, Argument
from pwncat.platform import Platform, Windows, Linux
from pwncat.util import random_string


gmtime = time_gmtime()
logfile_name = f"peass_log_{gmtime[3]}-{gmtime[4]}-{gmtime[4]}.log"


def log_output(logfile, current_line):
    """I liked to split printing log func, it classes my work."""
    # Please, don't use a text editor to read this logfile
    # read it with cat on terminal, or with type on windows cmd
    current_patched_line = current_line + "\n"
    with open(logfile, "a") as logfile_open:
        logfile_open.write(current_patched_line)


def stream_process(process, logfile):
    """This function allows the process to print the live output to our stdout."""
    go = process.poll() is None
    for line in process.stdout:
        current_line = line.rstrip().decode()
        log_output(logfile, current_line)
        print(current_line, flush=True)
    return go


def stream(process, logfile):
    """This is like short call for the stream_process func."""
    with open(logfile, "w") as logfile_open:
        logfile_open.write(
            "\x1b[30m------------------------------------------------------\n"
        )
        logfile_open.write("You SHOULD NOT use a text editor!\n")
        logfile_open.write(
            "Use `cat` command on terminal or `type` command on windows cmd!\n"
        )
        logfile_open.write(
            "------------------------------------------------------\x1b[0m\n"
        )

    while stream_process(process, logfile):
        sleep(0.1)


def mktemp(session: "pwncat.manager.Session", mode: str = "wb", suffix: str = ""):
    """This function helps to create temperory files."""
    platform = session.platform

    if not "." in suffix:
        suffix = "." + suffix

    if type(platform) == Windows:
        path = platform.Path(
            platform.powershell("$_ = [System.IO.Path]::GetTempPath() ; $_")[0]
        )

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
        "source": Argument(
            str,
            default="",
            help="source of Peass-ng file if it exist (default: download the file directly to the target)",
        )
    }

    def run(self, session: "pwncat.manager.Session", source: str):

        self.enumerate(session, source)
        yield Status(session)

    def enumerate(self, session: "pwncat.manager.Session", source):
        """This function where the PEAS-ng script is running."""
