#!/usr/bin/env python3
import enum

from pwncat.db import Fact


class ImplantType(enum.Flag):
    SPAWN = enum.auto()
    REPLACE = enum.auto()
    REMOTE = enum.auto()


class Implant(Fact):
    """ An installed implant """

    def __init__(self, source, types, uid):
        super().__init__(source=source, types=types)

        self.uid = uid

    def escalate(self, session: "pwncat.manager.Session"):
        """Escalate to the target user locally. Only valid for spawn or
        replace implants."""
        raise NotImplementedError()

    def trigger(self, target: "pwncat.target.Target"):
        """Trigger this implant for remote connection as the target user.
        This is only valid for remote implants."""

    def remove(self, session: "pwncat.manager.Session"):
        """ Remove this implant from the target """
