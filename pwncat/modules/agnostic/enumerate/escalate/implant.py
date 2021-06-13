#!/usr/bin/env python3

from pwncat.facts import Implant, ImplantType, EscalationSpawn, EscalationReplace
from pwncat.modules.enumerate import Schedule, EnumerateModule


class ImplantEscalationReplace(EscalationReplace):
    def __init__(self, implant: Implant):
        super().__init__(implant.source, None, implant.uid)

        self.implant: Implant = implant

    def escalate(self, session: "pwncat.manager.Session"):

        return self.implant.escalate(session)

    def title(self, session: "pwncat.manager.Session"):
        return f"""implant: {self.implant.title(session)}"""


class ImplantEscalationSpawn(EscalationSpawn):
    def __init__(self, implant: Implant):
        super().__init__(implant.source, None, implant.uid)

        self.implant: Implant = implant

    def escalate(self, session: "pwncat.manager.Session"):

        return self.implant.escalate(session)

    def title(self, session: "pwncat.manager.Session"):
        return f"""implant: {self.implant.title(session)}"""


class Module(EnumerateModule):
    """Generates escalation methods based on installed implants in
    order to facilitate their usage during automated escalation."""

    PLATFORM = None
    SCHEDULE = Schedule.ALWAYS
    PROVIDES = ["escalate.replace", "escalate.spawn"]

    def enumerate(self, session):

        for implant in session.run(
            "enumerate", types=["implant.replace", "implant.spawn"]
        ):
            if "implant.replace" in implant.types:
                yield ImplantEscalationReplace(implant)
            elif "implant.spawn" in implant.types:
                yield ImplantEscalationSpawn(implant)
