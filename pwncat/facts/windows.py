"""
Windows-specific facts which are used in multiple places throughout the framework.
"""
from enum import IntFlag
from typing import List, Callable, Optional
from datetime import datetime

import pwncat
from pwncat.facts import Fact, User, Group, ExecuteAbility
from pwncat.modules import ModuleFailed
from pwncat.platform import PlatformError


class LuidAttribute(IntFlag):
    DISABLED = 0x00000000
    SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x00000001
    SE_PRIVILEGE_ENABLED = 0x00000002
    SE_PRIVILEGE_REMOVED = 0x00000004
    SE_PRIVILEGE_USED_FOR_ACCESS = 0x80000000


class ProcessTokenPrivilege(Fact):
    """Describes a specific privilege"""

    def __init__(self, source: str, name: str, attributes: int, handle: int, pid: int):
        super().__init__(source=source, types=["token.privilege"])

        self.name = name
        self.attributes = LuidAttribute(attributes)
        self.handle = handle
        self.pid = pid

    def title(self, session: "pwncat.manager.Session"):
        attributes = str(self.attributes).removeprefix("LuidAttribute.").split("|")

        for i in range(len(attributes)):
            if attributes[i] == "DISABLED":
                attributes[i] = "[red]DISABLED[/red]"
            else:
                attributes[i] = f"[blue]{attributes[i]}[/blue]"

        return f"[cyan]{self.name}[/cyan] => {'|'.join(attributes)}"


class UserToken(ExecuteAbility):
    def __init__(self, source: str, uid: str, token: int):
        super().__init__(source=source, source_uid=None, uid=uid)
        self.types.append("token")

        self.token = token

    def can_impersonate(self, session: "pwncat.manager.Session"):
        """Test if the current session can impersonate tokens"""

        for priv in session.run("enumerate", types=["token.privilege"]):
            if (
                priv.name == "SeImpersonatePrivilege"
                and LuidAttribute.SE_PRIVILEGE_ENABLED in priv.attributes
            ):
                return True

        return False

    def title(self, session: "pwncat.manager.Session"):

        user = session.find_user(uid=self.uid)
        if user is None:
            user_name = f"SID({repr(self.uid)})"
        else:
            user_name = user.name

        if self.can_impersonate(session):
            return f"[red]Impersonatable[/red] [blue]{user_name}[/blue] Token: {self.token}"
        return f"[blue]{user_name}[/blue] Token: {self.token}"

    def shell(
        self, session: "pwncat.manager.Session"
    ) -> Callable[["pwncat.manager.Session"], None]:
        """Execute a new shell as the specified user. In this case, just impersonate the user."""

        if not self.can_impersonate(session):
            raise ModuleFailed("impersonate privilege not enabled")

        try:
            session.platform.impersonate(self.token)
        except PlatformError as exc:
            raise ModuleFailed(f"failed to impersonate token: {exc}")

        return lambda session: session.platform.revert_to_self()


class WindowsUser(User):
    """Windows-specific user data. This augments the :class:`User` class.

    :param source: the generating module
    :type source: str
    :param name: the name of the user
    :type name: str
    :param uid: the user identifier
    :type uid: str
    :param account_expires: the date/time when the account expires
    :type account_expires: Optional[datetime]
    :param description: description for this account
    :type description: str
    :param enabled: whether this account is enabled
    :type enabled: bool
    :param full_name: the full name of the user
    :type full_name: str
    :param password_changeable_date: the date/time when the password is changeable
    :type password_changeable_date: Optional[datetime]
    :param password_expires: the date/time when the password expires
    :type password_expires: Optional[datetime]
    :param user_may_change_password: whether the user can change their own password
    :type user_may_change_password: bool
    :param password_required: whether the password is required for login
    :type password_required: bool
    :param password_last_set: when the password was last changed
    :type password_last_set: Optional[datetime]
    :param last_logon: the last time the user logged in
    :type last_logon: Optional[datetime]
    :param principal_source: honestly, I'm not sure
    :type principal_source: str
    :param password: the user's password if known
    :type password: Optional[str] = None
    :param hash: the user's password hash if known
    :type hash: Optional[str] = None
    """

    def __init__(
        self,
        source: str,
        name: str,
        uid: str,
        account_expires: Optional[datetime],
        description: str,
        enabled: bool,
        full_name: str,
        password_changeable_date: Optional[datetime],
        password_expires: Optional[datetime],
        user_may_change_password: bool,
        password_required: bool,
        password_last_set: Optional[datetime],
        last_logon: Optional[datetime],
        principal_source: str,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        well_known: bool = False,
    ):
        super().__init__(
            source=source, name=name, uid=uid, password=password, hash=hash
        )

        self.account_expires: Optional[datetime] = account_expires
        self.user_description: str = description
        self.enabled: bool = enabled
        self.full_name: str = full_name
        self.password_changeable_date: Optional[datetime] = password_changeable_date
        self.password_expires: Optional[datetime] = password_expires
        self.user_may_change_password: bool = user_may_change_password
        self.password_required: bool = password_required
        self.password_last_set: Optional[datetime] = password_last_set
        self.last_logon: Optional[datetime] = last_logon
        self.principal_source: str = principal_source
        self.hidden: bool = well_known

    def __repr__(self):
        if self.password is None and self.hash is None:
            return f"""User(uid={self.id}, name={repr(self.name)})"""
        elif self.password is not None:
            return f"""User(uid={repr(self.id)}, name={repr(self.name)}, password={repr(self.password)})"""
        else:
            return f"""User(uid={repr(self.id)}, name={repr(self.name)}, hash={repr(self.hash)})"""


class WindowsGroup(Group):
    """Windows-specific group. This augments the :class:`Group` class.

    :param source: the generating module
    :type source: str
    :param name: the group name
    :type name: str
    :param gid: the group SID
    :type gid: str
    :param description: description for this group
    :type description: str
    :param principal_source: honestly, again, I have no clue
    :type principal_source: str
    :param members: list of SIDs for group members
    :type members: List[str]
    """

    def __init__(
        self,
        source: str,
        name: str,
        gid: str,
        description: str,
        principal_source: str,
        members: List[str],
        domain: Optional[str] = None,
    ):
        super().__init__(source=source, name=name, gid=gid, members=members)

        self.group_description: str = description
        self.principal_source: str = principal_source
        self.domain: Optional[str] = domain
