"""
Implant modules generate :class:`Implant` facts which provide the
ability to interact with the installed implant. Implants can be
one or more of spawn, replace or remote types. A spawn implant
is used to locally escalate privileges and spawns a new session.
A replace implant is also used to local escalation but instead
replaces the context of the current session with a different user.
Lastly, a remote implant allows pwncat to reconnect to the target.
"""
import enum
from typing import List, Union, Callable

import pwncat
from pwncat.db import Fact


class ImplantType(enum.Flag):
    """ Type of implant which was installed """

    SPAWN = enum.auto()
    """ Capable of spawning a new session to escalate privileges locally """
    REPLACE = enum.auto()
    """ Capable of replacing the current user context with the target user """
    REMOTE = enum.auto()
    """ Capable of reconnecting to the host later after disconnection """


class KeepImplantFact(Exception):
    """This is raised when removing an implant where the fact itself
    remains in the database, but the implant types are removed. Normally,
    this indicates that the implant was enumerated and not installed by
    pwncat. Removing the implant simply removes our ability to use it,
    but tracks the enumeration of the data."""


class Implant(Fact):
    """Abstract base implant class. Any fact which specifies an ``implant.*``
    type must implement this interface, however they are not required to
    inherit from this class (due to Python's duck typing). This is most
    notably utilized with :class:`pwncat.facts.PrivateKey` enumeration.

    :param source: generating module name
    :type source: str
    :param types: list of fact types
    :type types: List[str]
    :param uid: target UID
    :type uid: Union[int, str]
    """

    def __init__(self, source: str, types: List[str], uid: Union[int, str]):
        super().__init__(source=source, types=types)

        self.uid = uid

    def escalate(
        self, session: "pwncat.manager.Session"
    ) -> Union["pwncat.manager.Session", Callable[["pwncat.manager.Session"], None]]:
        """
        Escalate to the target user locally. If the implant type is ``implant.replace``, this
        method should replace the current user context with the target user and return a
        callable which can undo this action. The callable takes a session its' single argument.
        If the implant type is ``implant.spawn``, this method spawns a new session as the target
        user and returns the newly established session.

        :param session: the target session on which to act
        :type session: pwncat.manager.Session
        :rtype: Union[pwncat.manager.Session, Callable[[pwncat.manager.Session], None]]
        """
        raise NotImplementedError()

    def trigger(self, target: "pwncat.target.Target") -> "pwncat.manager.Session":
        """Trigger a remote implant and establish a new session. This is only valid for
        ``implant.remote`` implant types. It should return the newly established session.

        :param target: the database target object with the details on how to connect
        :type target: pwncat.target.Target
        :rtype: pwncat.manager.Session
        """

    def remove(self, session: "pwncat.manager.Session"):
        """Remove this implant from the target.

        :param session: the session on which to act
        :type session: pwncat.manager.Session
        """
