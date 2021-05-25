#!/usr/bin/env python3
from typing import List, Optional
from datetime import datetime

from pwncat.facts import User, Group


class WindowsUser(User):
    """ Windows-specific user """

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


class WindowsGroup(Group):
    """ Windows-specific group """

    def __init__(
        self,
        source: str,
        name: str,
        gid: str,
        description: str,
        principal_source: str,
        members: List[str],
    ):
        super().__init__(source=source, name=name, gid=gid, members=members)

        self.group_description: str = description
        self.principal_source: str = principal_source
