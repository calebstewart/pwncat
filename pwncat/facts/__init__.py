#!/usr/bin/env python3
import pathlib
import tempfile
from typing import IO, Callable, Optional

import rich.markup
from pwncat.db import Fact
from pwncat.channel import ChannelError
from pwncat.modules import ModuleFailed
from persistent.list import PersistentList
from pwncat.facts.tamper import *
from pwncat.facts.ability import *
from pwncat.facts.implant import *
from pwncat.facts.escalate import *


class Group(Fact):
    """Basic representation of a user group on the target system. Individual
    platform enumeration modules may subclass this to implement other user
    properties as needed for their platform."""

    def __init__(self, source: str, name: str, gid, members):
        super().__init__(["group"], source)

        self.name: str = name
        self.id = gid
        self.members: PersistentList = PersistentList(members)

    def __repr__(self):
        return f"""Group(gid={self.id}, name={repr(self.name)}, members={repr(self.members)})"""


class User(Fact):
    """Basic representation of a user on the target system. Individual platform
    enumeration modules may subclass this to implement other user properties as
    needed for their platform."""

    def __init__(
        self,
        source: str,
        name,
        uid,
        password: Optional[str] = None,
        hash: Optional[str] = None,
    ):
        super().__init__(["user"], source)

        self.name: str = name
        self.id = uid
        self.password: Optional[str] = None
        self.hash: Optional[str] = None

    def __repr__(self):
        if self.password is None and self.hash is None:
            return f"""User(uid={self.id}, name={repr(self.name)})"""
        elif self.password is not None:
            return f"""User(uid={repr(self.id)}, name={repr(self.name)}, password={repr(self.password)})"""
        else:
            return f"""User(uid={repr(self.id)}, name={repr(self.name)}, hash={repr(self.hash)})"""


class PotentialPassword(Fact):
    """A password possible extracted from a remote file
    `filepath` and `lineno` may be None signifying this
    password did not come from a file directly.
    """

    def __init__(self, source, password, filepath, lineno, uid):
        super().__init__(source=source, types=["creds.password"])

        self.password: str = password
        self.filepath: str = filepath
        self.lineno: int = lineno
        self.uid: int = uid  # We are Linux-specific here so this can be a literal UID

    def title(self, session):
        if self.password is not None:
            result = f"Potential Password [cyan]{rich.markup.escape(repr(self.password))}[/cyan]"
            if self.uid is not None:
                result += f" for [blue]{rich.markup.escape(session.find_user(uid = self.uid).name)}[/blue]"
            if self.filepath is not None:
                result += f" ({rich.markup.escape(self.filepath)}:{self.lineno})"
        else:
            result = f"Potential Password at [cyan]{rich.markup.escape(self.filepath)}[/cyan]:{self.lineno}"

        return result


class PrivateKey(Implant):
    """A private key found on the remote file system or known
    to be applicable to this system in some way. This fact can
    also act as an implant. By default, removing the implant will
    only remove the implant types from the fact. It is assumed that
    the key was enumerated and not installed. If connection or escalation
    fails, the `authorized` property is set to False and the implant
    types are automatically removed."""

    def __init__(self, source, path, uid, content, encrypted, authorized: bool = True):
        super().__init__(
            source=source,
            uid=uid,
            types=["creds.private_key", "implant.replace", "implant.remote"],
        )

        self.uid: int = uid
        """ The uid we believe the private key belongs to """
        self.path: str = path
        """ The path to the private key on the remote host """
        self.content: str = content
        """ The actual content of the private key """
        self.encrypted: bool = encrypted
        """ Is this private key encrypted? """
        self.authorized: bool = authorized

    def title(self, session: "pwncat.manager.Session"):
        user = session.find_user(uid=self.uid)

        return f"Private key owned by [blue]{user.name}[/blue] at [cyan]{rich.markup.escape(self.path)}[/cyan]"

    def description(self, session) -> str:
        return self.content

    def remove(self, session: "pwncat.manager.Session"):
        """ Remove the implant types from this private key """

        raise KeepImplantFact()

    def escalate(self, session: "pwncat.manager.Session"):
        """ Escalate to the owner of this private key with a local ssh call """

        if not self.authorized:
            raise ModuleFailed("key is not authorized or failed")

        if session.platform.which("ssh") is None:
            raise ModuleFailed("no local ssh binary")

        current_user = session.current_user()
        user = session.find_user(uid=self.uid)

        # Upload the private key
        with session.platform.tempfile(suffix="", mode="w") as dest:
            privkey_path = dest.name
            dest.write(self.content)

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
            self.authorized = False
            self.types.remove("implant.replace")
            self.types.remove("implant.remote")
            session.db.transaction_manager.commit()
            raise ModuleFailed(
                f"ssh to localhost failed w/ exit code {proc.returncode}"
            )

        # Detach the popen object
        proc.detach()

        return lambda session: session.platform.channel.send(b"exit\n")

    def trigger(
        self, manager: "pwncat.manager.Manager", target: "pwncat.target.Target"
    ):
        """ Connect remotely to this target with the specified user and key """

        if not self.authorized:
            raise ModuleFailed("key is not authorized or failed")

        # Find the user for this UID
        for fact in target.facts:
            if "user" in fact.types and fact.id == self.uid:
                user = fact
                break
        else:
            raise ModuleFailed(f"unknown username for uid={self.uid}")

        with tempfile.NamedTemporaryFile("w") as filp:
            filp.write(self.content)
            filp.flush()

            pathlib.Path(filp.name).chmod(0o600)

            try:
                # Connect via SSH
                session = manager.create_session(
                    "linux",
                    host=target.public_address[0],
                    user=user.name,
                    identity=filp.name,
                )
            except ChannelError as exc:
                manager.log(
                    f"[yellow]warning[/yellow]: {self.source} implant failed; removing implant types."
                )
                self.authorized = False
                self.types.remove("implant.remote")
                self.types.remove("implant.replace")
                raise ModuleFailed(str(exc)) from exc

            return session


class EscalationReplace(Fact):
    """Performs escalation and transforms the current session into the context
    of the specified user.

    :param source: the name of the generating module
    :type source: str
    :param source_uid: the starting uid needed to use this escalation
    :param uid: the target uid for this escalation
    """

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["escalate.replace"], source=source)

        self.source_uid = source_uid
        self.uid = uid

    def escalate(
        self, session: "pwncat.manager.Session"
    ) -> Callable[["pwncat.manager.Session"], None]:
        """Execute the escalation optionally returning a new session

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :returns: Callable - A lambda taking the session and exiting the new shell
        """


class EscalationSpawn(Fact):
    """Performs escalation and spawns a new session in the context of the
    specified user. The execute method will return the new session.

    :param source: the name of the generating module
    :type source: str
    :param source_uid: the starting uid needed to use this escalation
    :param uid: the target uid for this escalation
    """

    def __init__(self, source, source_uid, uid):
        super().__init__(types=["escalate.spawn"], source=source)

        self.source_uid = source_uid
        self.uid = uid

    def execute(self, session: "pwncat.manager.Session") -> "pwncat.manager.Session":
        """Spawn a new session under the context of a new user

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :returns: pwncat.manager.Session - a newly established session as the specified user
        """
