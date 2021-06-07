#!/usr/bin/env python3

from pwncat.facts import ArchData, DistroVersionData, HostnameData
from pwncat.facts.windows import WindowsUser
from pwncat.modules import ModuleFailed, Status
from pwncat.modules.enumerate import EnumerateModule, Schedule
from pwncat.platform.windows import PowershellError, Windows
from pwncat.util import random_string


class Module(EnumerateModule):
    """Enumerate windows system information"""

    PROVIDES = ["system.distro", "system.arch", "system.hostname"]
    PLATFORM = [Windows]
    SCHEDULE = Schedule.ONCE

    def enumerate(self, session: "pwncat.manager.Session"):

        query_system_info = """
        function query_sysinfo {
          $os_info = (Get-CimInstance Win32_operatingsystem)
          $hostname = [System.Net.Dns]::GetHostName()

          [PsCustomObject]@{
            HostName = $hostname;
            BuildNumber = $os_info.BuildNumber;
            BuildType = $os_info.BuildType;
            CountryCode = $os_info.CountryCode;
            TimeZone = $os_info.CurrentTimeZone;
            DEP = [PsCustomObject]@{
              Available = $os_info.DataExecutionPrevention_Available;
              Available32 = $os_info.DataExecutionPrevention_32bitApplications;
              Drivers = $os_info.DataExecutionPrevention_Drivers;
              SupportPolicy = $os_info.DataExecutionPrevention_SupportPolicy;
            };
            Debug = $os_info.Debug;
            Description = $os_info.Description;
            InstallDate = $os_info.InstallDate;
            LastBootUpTime = $os_info.LastBootUpTime;
            Name = $os_info.Name;
            Architecture = $os_info.OSArchitecture;
            Language = $os_info.OSLanguage;
            Suite = $os_info.OSProductSuite;
            Type = $os_info.OSType;
            ServicePackMajor = $os_info.ServicePackMajorVersion;
            ServicePackMinor = $os_info.ServicePackMinorVersion;
            Version = $os_info.Version;
          }
        }
        query_sysinfo
        """.replace(
            "query_sysinfo", random_string(8)
        )

        try:
            info = session.platform.powershell(query_system_info)[0]
        except PowershellError as exc:
            raise ModuleFailed(f"failed to load sysinfo function: {exc}")

        yield DistroVersionData(
            self.name,
            info["Name"].split("|")[0],
            info["BuildType"],
            info["BuildNumber"],
            info["Version"],
        )

        yield HostnameData(self.name, info["HostName"])

        yield ArchData(self.name, info["Architecture"])
