#!/usr/bin/env python3
import json
from typing import List, Optional

import pkg_resources

from pwncat.db import Fact
from pwncat.facts import ArchData, HostnameData
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class KernelVersionData(Fact):
    """
    Represents a W.X.Y-Z kernel version where W is the major version,
    X is the minor version, Y is the patch, and Z is the ABI.

    This explanation came from here:
        https://askubuntu.com/questions/843197/what-are-kernel-version-number-components-w-x-yy-zzz-called
    """

    def __init__(self, source, major, minor, patch, abi):
        super().__init__(source=source, types=["system.kernel.version"])

        self.major: int = major
        self.minor: int = minor
        self.patch: int = patch
        self.abi: str = abi

    def title(self, session):
        return (
            f"Running Linux Kernel [red]{self.major}[/red]."
            f"[green]{self.minor}[/green]."
            f"[blue]{self.patch}[/blue]-[cyan]{self.abi}[/cyan]"
        )


class KernelVulnerabilityData(Fact):
    """
    Data describing a kernel vulnerability which appears to be exploitable
    on the remote host. This is **not** guaranteed to be exploitable, however
    the kernel version number lines up. The `working` property can be
    modified by other modules (e.g. escalate modules) after attempting this
    vulnerability.
    """

    def __init__(self, source, name, versions, link, cve):
        super().__init__(source=source, types=["system.kernel.vuln"])

        self.name: str = name
        self.versions: List[str] = versions
        self.link: Optional[str] = link
        self.cve: Optional[str] = cve
        # All exploits are assumed working, but can be marked as not working
        self.working: bool = True

    def title(self, title):
        line = f"[red]{self.name}[/red]"
        if self.cve is not None:
            line += f" ([cyan]CVE-{self.cve}[/cyan])"
        return line

    def description(self, title):
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
    common Linux Exploit Suggester, and will report known
    vulnerabilities which are applicable to the detected
    kernel version.
    """

    PROVIDES = [
        "system.kernel.version",
        "system.hostname",
        "system.arch",
        "system.kernel.vuln",
    ]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session):
        """Run uname and organize information"""

        # Grab the uname output
        output = session.platform.run(
            "uname -s -n -r -m -o", capture_output=True, text=True, check=True
        )

        fields = output.stdout.split(" ")

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
        version = KernelVersionData(self.name, int(w), int(x), int(y), z)
        yield version

        # Handle arch
        yield ArchData(self.name, machine_name)

        # Handle Hostname
        yield HostnameData(self.name, hostname)

        # Handle Kernel vulnerabilities
        with open(
            pkg_resources.resource_filename("pwncat", "data/lester.json")
        ) as filp:
            vulns = json.load(filp)

            version_string = f"{version.major}.{version.minor}.{version.patch}"
            for name, vuln in vulns.items():
                if version_string not in vuln["vuln"]:
                    continue
                yield KernelVulnerabilityData(
                    self.name,
                    name,
                    vuln["vuln"],
                    vuln.get("mil", None),
                    vuln.get("cve", None),
                )
