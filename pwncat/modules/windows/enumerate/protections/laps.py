#!/usr/bin/env python3

from typing import Dict

from pwncat.db import Fact
from pwncat.modules import ModuleFailed
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import EnumerateModule


class LAPSData(Fact):
    def __init__(self, source, registry_values: Dict):
        super().__init__(source=source, types=["protections.laps"])

        self.registry_values: bool = registry_values
        """ The current setting for LAPS"""

    def __getitem__(self, name):

        return self.registry_values[name]

    def title(self, session):
        if not self.registry_values["AdmPwdEnabled"]:
            return "AdmPwdEnabled (LAPS) is [bold green]inactive[/bold green]"

        return "AdmPwdEnabled (LAPS) is [bold red]active[/bold red]"

    def description(self, session):

        mappings = {
            "AdmPwdEnabled": {
                True: "[red]LAPS is [bold]active[/bold][/red]",
                False: "[green]LAPS is [bold]inactive[/bold][/green]",
            },
            "PDSList": {
                True: "[red]configured to use PDS[/red]",
                False: "[green][bold]not[/bold] configured to use PDS[/green]",
            },
            "UseSharedSPN": {
                True: "[red]PDS service runs under domain account[/red]",
                False: "[green]PDS service does [bold]not[/bold] run under domain account[/green]",
            },
            "ManualPasswordChangeProtectionEnabled": {
                True: "[red]manual password change is [bold]not allowed[/bold][/red]",
                False: "[green]manual password change [bold]is allowed[/bold][/green]",
            },
            "PwdExpirationProtectionEnabled": {
                True: "[red]password expiration policy is [bold]active[/bold][/red]",
                False: "[green]password expiration policy is [bold]inactive[/bold][/green]",
            },
            "PwdHistoryEnabled": {
                True: "[red]password history is [bold]maintained[/bold][/red]",
                False: "[green]password history is [bold]not maintained[/bold][/green]",
            },
            "PwdEncryptionEnabled": {
                True: "[red]password encryption is [bold]enabled[/bold][/red]",
                False: "[green]password encryption is [bold]not enabled[/bold][/green]",
            },
            # "EncryptionKey" : {},
            # "PublicKey" : {},
            # "AdministratorAccountName" : {},
            # "LogLevel" : {},
            # "MaxPasswordAge" : {},
            # "PasswordComplexity" : {},
        }

        output = []
        for registry_name in self.registry_values.keys():
            # Ingore the big LAPS property we have already displayed
            if registry_name == "AdmPwdEnabled":
                continue
            registry_value = self.registry_values[registry_name]
            if registry_name in mappings.keys():
                output.append(
                    f"[cyan]{registry_name}[/cyan] = {registry_value} : {mappings[registry_name][registry_value]}"
                )
            else:
                if not registry_value:
                    output.append(
                        f"[cyan]{registry_name}[/cyan] [green]not set[/green]"
                    )
                else:
                    output.append(f"[cyan]{registry_name}[/cyan] = {registry_value}")

        return "\n".join((" - " + line for line in output))


class Module(EnumerateModule):
    """Enumerate the current LAPS and password policy settings on the target"""

    PROVIDES = ["protections.laps"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        # Reference:
        # https://getadmx.com/HKLM/Software/Policies/Microsoft%20Services/AdmPwd

        registry_key = "HKLM:\\Software\\Policies\\Microsoft Services\\AdmPwd\\"

        registry_values = {
            "PDSList": bool,
            "UseSharedSPN": bool,
            "ManualPasswordChangeProtectionEnabled": bool,
            "PwdExpirationProtectionEnabled": bool,
            "PwdEncryptionEnabled": bool,
            "EncryptionKey": str,
            "PublicKey": str,
            "AdminAccountName": str,
            "LogLevel": int,
            "MaxPasswordAge": int,
            "PasswordComplexity": int,
            "PasswordLength": int,
            "PasswordAge": int,
            "AdmPwdEnabled": bool,
            "SupportedForests": str,
            "PwdExpirationProtectionEnabled": bool,
            "AdminAccountName": bool,
        }

        for registry_value, registry_type in registry_values.items():
            try:
                result = session.platform.powershell(
                    f"Get-ItemPropertyValue '{registry_key}' -Name '{registry_value}'"
                )

                if not result:
                    raise ModuleFailed(
                        f"failed to retrieve registry value {registry_value}"
                    )

                registry_values[registry_value] = registry_type(result[0])

            except PowershellError as exc:
                if "does not exist" in exc.message:
                    registry_values[registry_value] = registry_type(0)
                else:
                    raise ModuleFailed(
                        f"could not retrieve registry value {registry_value}: {exc}"
                    ) from exc

        yield LAPSData(self.name, registry_values)
