#!/usr/bin/env python3

import pwncat
from pwncat.facts import ExecuteAbility, EscalationReplace
from pwncat.modules.enumerate import Schedule, EnumerateModule


class DirectReplaceAbility(EscalationReplace):
    def __init__(self, source, ability: ExecuteAbility):
        super().__init__(source, ability.source_uid, ability.uid)

        self.ability: ExecuteAbility = ability

    def escalate(self, session: "pwncat.manager.Session"):

        return self.ability.shell(session)

    def title(self, session: "pwncat.manager.Session"):
        return self.ability.title(session)


class Module(EnumerateModule):
    """Locate execute abilities and produce escalation methods from them.
    This module produces EscalationReplace results which replace the active
    user in the running session with the new user."""

    PLATFORM = None
    SCHEDULE = Schedule.ALWAYS
    PROVIDES = ["escalate.replace"]

    def enumerate(self, session: "pwncat.manager.Session"):

        for ability in session.run("enumerate", types=["ability.execute"]):
            yield DirectReplaceAbility(self.name, ability)
