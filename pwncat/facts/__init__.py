"""
Generic facts used for standard enumerations. Some fact types are
used for multiple platforms, so they were separated out here. You
should not generally need to use these types except as reference
when interacting with data returned by an enumeration module.
"""
import time
import pathlib
import tempfile
import subprocess
from io import StringIO
from typing import Callable, Optional

import rich.markup
from persistent.list import PersistentList

import pwncat
from pwncat.db import Fact
from pwncat.channel import ChannelError
from pwncat.modules import ModuleFailed
from pwncat.platform import PlatformError
from pwncat.facts.tamper import (  # noqa: F401
    Tamper,
    CreatedFile,
    ReplacedFile,
    CreatedDirectory,
)
from pwncat.facts.ability import (  # noqa: F401
    GTFOExecute,
    GTFOFileRead,
    SpawnAbility,
    GTFOFileWrite,
    ExecuteAbility,
    FileReadAbility,
    FileWriteAbility,
    build_gtfo_ability,
)
from pwncat.facts.implant import Implant, ImplantType, KeepImplantFact  # noqa: F401


class ArchData(Fact):
    """
    Simply the architecture of the remote machine. This class
    wraps the architecture name in a nicely printable data
    class.

    :param source: module which generated this fact
    :type source: str
    :param arch: the name of the architecture
    :type arch: str
    """

    def __init__(self, source, arch):
        super().__init__(source=source, types=["system.arch"])

        self.arch: str = arch
        """ The determined architecture. """

    def title(self, session):
        return f"Running on a [cyan]{self.arch}[/cyan] processor"


class HostnameData(Fact):
    """
    The hostname of this target as retrieved from the target itself.
    This is not guaranteed to be resolvable, and is simply the name
    which the  target uses for itself (e.g. from the ``hostname``
    command).

    :param source: module which generated this fact
    :type source: str
    :param hostname: the hostname of the target
    :type hostname: str
    """

    def __init__(self, source, hostname):
        super().__init__(source=source, types=["system.hostname"])

        self.hostname: str = hostname
        """ The determined architecture. """

    def title(self, session):
        return f"[cyan]{self.hostname}[/cyan]"


class DistroVersionData(Fact):
    """OS Distribution and version information

    :param source: module which generated this fact
    :type source: str
    :param name: the name of the target operating system
    :type name: str
    :param ident: identifier for this specific distro
    :type ident: str
    :param build_id: the build identifier for this OS
    :type build_id: str
    :param version: the version of the installed OS
    :type version: str
    """

    def __init__(self, source, name, ident, build_id, version):
        super().__init__(source=source, types=["system.distro"])

        self.name: str = name
        self.ident: str = ident
        self.build_id: str = build_id
        self.version: str = version

    def title(self, session):
        return (
            f"[blue]{rich.markup.escape(str(self.name))}[/blue] ([cyan]{rich.markup.escape(self.ident)}[/cyan]), "
            f"Version [red]{rich.markup.escape(str(self.version))}[/red], "
            f"Build ID [green]{rich.markup.escape(str(self.build_id))}[/green]."
        )


class Group(Fact):
    """Basic representation of a user group on the target system. Individual
    platform enumeration modules may subclass this to implement other user
    properties as needed for their platform.

    :param source: module which generated this fact
    :type source: str
    :param name: the name of the group
    :type name: str
    :param id: the unique group identifier
    :type id: Union[int, str]
    :param members: a list of unique UIDs who are members of this group
    :type members: List[Union[int,str]]
    """

    def __init__(self, source: str, name: str, gid, members):
        super().__init__(["group"], source)

        self.name: str = name
        self.id = gid
        self.members: PersistentList = PersistentList(members)

    def title(self, session: "pwncat.manager.Session"):

        members = []
        for uid in self.members:
            user = session.find_user(uid=uid)

            if user is None and not isinstance(uid, int):
                user = session.find_group(gid=uid)

            if user is None:
                members.append(f"UID({repr(uid)})")
            else:
                members.append(user.name)

        return f"""Group(gid={repr(self.id)}, name={repr(self.name)}, members={repr(members)})"""


class User(Fact):
    """Basic representation of a user on the target system. Individual platform
    enumeration modules may subclass this to implement other user properties as
    needed for their platform.

    :param source: module which generated this fact
    :type source: str
    :param name: name of the user
    :type name: str
    :param uid: unique identifier for this user
    :type uid: Union[int, str]
    :param password: the password if known
    :type password: Optional[str]
    :param hash: the password hash if known
    :type hash: Optional[str]
    """

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

    :param source: module which generated this fact
    :type source: str
    :param password: the suspected password
    :type password: str
    :param filepath: the file where we found the password
    :type filepath: str
    :param lineno: the line number where the password was found
    :type lineno: int
    :param uid: the user ID for which this password is suspected
    :type uid: Union[int, str]
    """

    def __init__(self, source, password, filepath, lineno, uid):
        super().__init__(source=source, types=["creds.password"])

        self.password: str = password
        self.filepath: str = filepath
        self.lineno: int = lineno
        self.uid: int = uid

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
    types are automatically removed.

    :param source: module which generated this fact
    :type source: str
    :param path: path to the private key on the target
    :type path: str
    :param uid: the user for which the key was found
    :type uid: Union[int, str]
    :param content: content of the private key
    :type content: str
    :param encrypted: whether the key is encrypted
    :type encrypted: bool
    :param authorized: whether this key is authorized for the user
    :type authorized: bool
    """

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
        """Remove the implant types from this private key"""

        raise KeepImplantFact()

    def escalate(self, session: "pwncat.manager.Session"):
        """Escalate to the owner of this private key with a local ssh call"""

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
        """Connect remotely to this target with the specified user and key"""

        if not self.authorized:
            raise ModuleFailed("key is not authorized or failed")

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
                identity=StringIO(self.content + "\n"),
            )
        except (ChannelError, PlatformError) as exc:
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
    of the specified user. This is a base class for escalations.

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
    specified user. The execute method will return the new session. This
    is a base class for escalations.

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
