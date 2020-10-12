#!/usr/bin/env python3
from typing import List, Optional
import dataclasses
import pkg_resources
import json

import pwncat
from pwncat.platform import Platform
from pwncat import util
from pwncat.modules.enumerate import EnumerateModule, Schedule


@dataclasses.dataclass
class ArchData:
    """
    Simply the architecture of the remote machine. This class
    wraps the architecture name in a nicely printable data
    class.
    """

    arch: str
    """ The determined architecture. """

    def __str__(self):
        return f"Running on a [cyan]{self.arch}[/cyan] processor"


@dataclasses.dataclass
class KernelVersionData:
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.

    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    major: int
    minor: int
    patch: int
    abi: str

    def __str__(self):
        return (
            f"Running Linux Kernel [red]{self.major}[/red]."
            f"[green]{self.minor}[/green]."
            f"[blue]{self.patch}[/blue]-[cyan]{self.abi}[/cyan]"
        )


@dataclasses.dataclass
class KernelVulnerabilityData:
    """
    Data describing a kernel vulnerability which appears to be exploitable
    on the remote host. This is **not** guaranteed to be exploitable, however
    the kernel version number lines up. The `working` property can be
    modified by other modules (e.g. escalate modules) after attempting this
    vulnerability.
    """

    name: str
    versions: List[str]
    link: Optional[str]
    cve: Optional[str]
    # All exploits are assumed working, but can be marked as not working
    working: bool = True

    def __str__(self):
        line = f"[red]{self.name}[/red]"
        if self.cve is not None:
            line += f" ([cyan]CVE-{self.cve}[/cyan])"
        return line

    @property
    def description(self):
        line = f"Affected Versions: {repr(self.versions)}\n"
        if self.link:
            line += f"Details: {self.link}"
        return line


class Module(EnumerateModule):
    """
    Enumerate standard system properties provided by the
    `uname` command. This will enumerate the kernel name,
    version, hostname (nodename), machine hardware name,
    and operating system name (normally GNU/Linux).

    This module also provides a similar enumeration to the
    common Linux Exploit Suggestor, and will report known
    vulnerabilities which are applicable to the detected
    kernel version.
    """

    PROVIDES = [
        "system.kernel.version",
        "system.hostname",
        "system.arch",
        "system.kernel.vuln",
    ]
    PLATFORM = Platform.LINUX
    SCHEDULE = Schedule.ONCE

    def enumerate(self):
        """ Run uname and organize information """

        # Grab the uname output
        output = pwncat.victim.run("uname -s -n -r -m -o").decode("utf-8").strip()
        fields = output.split(" ")

        # Grab the components
        # kernel_name = fields[0] if fields else None
        hostname = fields[1] if len(fields) > 1 else None
        kernel_revision = fields[2] if len(fields) > 2 else None
        machine_name = fields[3] if len(fields) > 3 else None
        # operating_system = fields[4] if len(fields) > 4 else None

        # Handle kernel versions
        w, x, *y_and_z = kernel_revision.split(".")
        y_and_z = ".".join(y_and_z).split("-")
        y = y_and_z[0]
        z = "-".join(y_and_z[1:])
        version = KernelVersionData(int(w), int(x), int(y), z)
        yield "system.kernel.version", version

        # Handle arch
        yield "system.arch", ArchData(machine_name)

        # Handle Hostname
        yield "system.hostname", hostname

        # Handle Kernel vulnerabilities
        with open(
            pkg_resources.resource_filename("pwncat", "data/lester.json")
        ) as filp:
            vulns = json.load(filp)

            version_string = f"{version.major}.{version.minor}.{version.patch}"
            for name, vuln in vulns.items():
                if version_string not in vuln["vuln"]:
                    continue
                yield "system.kernel.vuln", KernelVulnerabilityData(
                    name, vuln["vuln"], vuln.get("mil", None), vuln.get("cve", None)
                )
