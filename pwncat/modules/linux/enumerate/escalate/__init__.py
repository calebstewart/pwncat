#!/usr/bin/env python3
from typing import Callable

from pwncat.db import Fact
from pwncat.manager import Session


class EscalationExisting(Fact):
    """ Escalation step which replaces the active session with a new user """

    def __init__(self, source, uid):
        super().__init__(source=source, types=["escalate.existing"])

        self.uid = uid

    def escalate(self, session) -> Callable[[Session], None]:
        """ Escalate the current session to the new user """


class EscalationReplace(Fact):
    """ Escalation step which spawns a new session as a different user """

    def __init__(self, source, uid):
        super().__init__(source=source, types=["escalate.replace"])

        self.uid = uid

    def execute(self, session) -> Session:
        """ Execute a new session as a new user """
