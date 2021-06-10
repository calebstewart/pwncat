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


class UACData(Fact):
    def __init__(self, source, registry_values: Dict):
        super().__init__(source=source, types=["protections.uac"])

        self.registry_values: bool = registry_values
        """ The current setting for UAC"""

    def __getitem__(self, name):
        return self.registry_values[name]

    def title(self, session):
        if not self.registry_values["EnableLUA"]:
            return "UserAccountControl (UAC) is [bold green]inactive[/bold green]"

        return "UserAccountControl (UAC) is [bold red]active[/bold red]"

    def description(self, session):
        output = []
        if self.registry_values["EnableLUA"]:
            consent_prompt = self.registry_values["ConsentPromptBehaviorAdmin"]
            if consent_prompt == 0:
                output.append(
                    f"'ConsentPromptBehaviorAdmin' = {consent_prompt}: [bold green]UAC will not prompt[/bold green]"
                )
            if consent_prompt == 1 or consent_prompt == 3:
                output.append(
                    f"'ConsentPromptBehaviorAdmin' = {consent_prompt}: [red]admin is asked for [bold]credentials[/bold][/red]"
                )
            if consent_prompt == 2 or consent_prompt == 4:
                output.append(
                    f"'ConsentPromptBehaviorAdmin' = {consent_prompt}: [red]admin is asked for [bold]confirmation[/bold][/red]"
                )
            if consent_prompt == 5:
                output.append(
                    f"'ConsentPromptBehaviorAdmin' = {consent_prompt} (default): [red]admin is asked for [bold]confirmation[/bold][/red]"
                )

            local_account = self.registry_values["LocalAccountTokenFilterPolicy"]
            if local_account == False:
                output.append(
                    f"'LocalAccountTokenFilterPolicy' = {local_account} (default): [red]only the built-in admin can perform admin tasks without UAC[/red]"
                )
            else:
                output.append(
                    f"'LocalAccountTokenFilterPolicy' = {local_account}: [yellow]all accounts in the Administrators group can perform admin tasks without UAC[/yellow]"
                )

            filter_token = self.registry_values["FilterAdministratorToken"]
            if filter_token == False:
                output.append(
                    f"'FilterAdministratorToken' = {local_account} (default): [yellow]the built-in admin [bold]can[/bold] do remote administration[/yellow]"
                )
            else:
                if local_account == 1:
                    output.append(
                        f"'FilterAdministratorToken' = {local_account}: [yellow]the built-in admin [bold]can[/bold] do remote administration since 'LocalAccountTokenFilterPolicy' is {local_account}[/yellow]"
                    )
                else:
                    output.append(
                        f"'FilterAdministratorToken' = {local_account}: [red]the built-in admin [bold]cannot[/bold] do remote administration[/red]"
                    )
        else:
            return (
                None  # this is a shortform fact, so it just display only the title line
            )

        return "\n".join((" - " + line for line in output))


class Module(EnumerateModule):
    """Enumerate the current Windows Defender settings on the target"""

    PROVIDES = ["protections.uac"]
    PLATFORM = [Windows]

    def enumerate(self, session):

        # Reference:
        # https://book.hacktricks.xyz/windows/authentication-credentials-uac-and-efs#uac

        registry_key = (
            "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\"
        )

        registry_values = {
            "EnableLUA": bool,
            "ConsentPromptBehaviorAdmin": int,
            "LocalAccountTokenFilterPolicy": bool,
            "FilterAdministratorToken": bool,
        }

        for registry_value, registry_type in registry_values.items():
            try:
                result = session.platform.powershell(
                    f"Get-ItemPropertyValue {registry_key} -Name {registry_value}"
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

            yield UACData(self.name, registry_values)
