#!/usr/bin/env python3
from typing import BinaryIO, Optional

from pwncat.db import Fact


class FileReadAbility(Fact):
    """ Ability to read a file as a different user """

    def __init__(self, source, uid):
        super().__init__(types=["escalate.ability.file_read"], source=source)

        self.uid = uid

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ):
        """ Open a file for reading. This method mimics the builtin open
        function, and returns a file-like object for reading. """

class FileWriteAbility(Fact):
    """ Ability to write a file as a different user """

    def __init__(self, source, uid):
        super().__init__(types=["escalate.ability.file_write"], source=source)

        self.uid = uid

    def open(
        self,
        session,
        path: str,
        mode: str = "r",
        buffering: int = -1,
        encoding: str = "utf-8",
        errors: str = None,
        newline: str = None,
    ):
        """ Open a file for writing. This method mimics the builtin open
        function and returns a file-like object for writing. """


class ExecuteAbility(Fact):
    """ Ability to execute a binary as a different user """

    def __init__(self, source, uid):
        super().__init__(types=["escalate.ability.execute"], source=source)

        self.uid = uid

    def execute(self, session: "pwncat.manager.Session" path):
        """ Exectue the given binary in the current session as another user """


class SpawnAbility(Fact):
    """ Ability to spawn a new process as a different user without communications """

    def __init__(self, source, uid):
        super().__init__(types=["escalate.ability.spawn"], source=source)

    def execute(self, session: "pwncat.manager.Session", path):
        """ Execute the given binary outside of this session w/ no IO """


class EscalationStep(Fact):
    """Performs escalation to either transform the current session into
    a new user or create a new session as the requested user."""

    def __init__(self, source, uid):
        super().__init__(types=["escalate.step"], source=source)

        self.uid = uid

    def execute(self, session: "pwncat.manager.Session") -> Optional["pwncat.manager.Session"]:
        """ Execute the escalation optionally returning a new session """
