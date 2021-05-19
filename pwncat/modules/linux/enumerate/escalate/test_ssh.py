#!/usr/bin/env python3

from pwncat.facts import EscalationSpawn
from pwncat.channel import ChannelError
from pwncat.modules import ModuleFailed
from pwncat.modules.enumerate import Schedule, EnumerateModule
from pwncat.platform.linux import Linux


class TestNewSSHSession(EscalationSpawn):
    """ Escalation via SSH as root """

    def __init__(self, source):
        super().__init__(source=source, source_uid=1000, uid=1001)

    def escalate(self, session: "pwncat.manager.Manager") -> "pwncat.manager.Session":

        try:
            new_session = session.manager.create_session(
                "linux",
                host="pwncat-ubuntu",
                user="john",
                identity="/home/caleb/.ssh/id_rsa",
            )
        except ChannelError as exc:
            raise ModuleFailed(str(exc)) from exc

        return new_session

    def title(self, session):
        return "ssh to [cyan]pwncat-ubuntu[cyan] as [blue]john[/blue]"


class Module(EnumerateModule):
    """ Test enumeration to provide a EscalationSpawn fact """

    PROVIDES = ["escalate.spawn"]
    SCHEDULE = Schedule.ONCE
    PLATFORM = [Linux]

    def enumerate(self, session):
        yield TestNewSSHSession(self.name)
