#!/usr/bin/env python3
from typing import Optional, List, Tuple
import enum

import persistent
import persistent.list
from BTrees.OOBTree import TreeSet


class NAT(enum.Enum):
    """ Indicates the current known state of NAT on the target host """

    UNKNOWN = enum.auto()
    """ We currently don't have enough information to determine if NAT is used """
    ENABLED = enum.auto()
    """ NAT is definitely enabled. Public/private addresses differ. """
    DISABLED = enum.auto()
    """ NAT is definitely disabled. Public/private addresses are identical. """


class OS(enum.Enum):
    """Describes the operating system on the target host. This is normally
    set by the platform type when connecting, however may be interrogated
    from the target host directly. For example, in the case of similar OS's
    like Linux, Mac, and BSD, the platform may double check the OS prior to
    establishing a session.

    If the OS doesn't match your platform specifically, session establishment
    may fail, but any details collected so far will be stored (such as addresses
    and target OS information).
    """

    LINUX = enum.auto()
    """ A linux-based operating system """
    WINDOWS = enum.auto()
    """ Windows NT based operating system """
    MAC = enum.auto()
    """ Apple Mac OS """
    BSD = enum.auto()
    """ A BSD variant """
    UNKNOWN = enum.auto()
    """ Unknown Operatin System """


class Target(persistent.Persistent):
    """Describes collected data on a target host. This replaces the database
    in previous versions of pwncat. It collects enumeration facts, system info,
    persistence state, and any other contextual information stored across
    instances of pwncat. Properties added to this class are automatically stored
    in the ZODB database as described by your configuration.

    A target is initialized with no information, and has no requirement for what
    data is available. Depending on the state of the active connection (if any)
    and the type of system, some information may not be available. During
    construction of a new session, some information is automatically queried such
    as the public address (routable IP address from attacking perspective) and port
    number, internal address (IP address from perspective of target) and port,
    NAT state, hostname, and a platform specific unique identifier.
    """

    def __init__(self):

        self.name: Optional[str] = None
        """ An optional friendly name that can be used to refer to this target """
        self.public_address: Optional[Tuple[str, int]] = None
        """ Public address as routable by the attacker """
        self.internal_address: Optional[Tuple[str, int]] = None
        """ Internal address as viewed by the target """
        self.hostname: Optional[str] = None
        """ Hostname from the targets perspective """
        self.guid: Optional[str] = None
        """ Globally unique identifier normally determined by a platform
        specific algorithm. """
        self.os: OS = OS.UNKNOWN
        """ Target host operating system """
        self.facts: persistent.list.PersistentList = persistent.list.PersistentList()
        """ List of enumerated facts about the target host """
        self.tampers: persistent.list.PersistentList = persistent.list.PersistentList()
        """ List of files/properties of the target that have been modified and/or created. """
        self.users: persistent.list.PersistentList = persistent.list.PersistentList()
        """ List of users known on the target system (may not be all-encompasing depending on access) """
        self.utilities: TreeSet = TreeSet()
        """ Mapping of utility names to paths. This is mainly used on Unix platforms to identify binaries available in the path. """
        self.implants: persistent.list.PersistentList = persistent.list.PersistentList()
        """ List of installed implants on this target host """

    @property
    def nat(self) -> NAT:
        """Determine if NAT is applied for this host. This simply tests
        whether the target views it's IP in the same way we do. This simply
        compares the public and internal addresses to infer the state of NAT
        on the target network.
        """

        if self.public_address is None or self.internal_address is None:
            return NAT.UNKNOWN

        return (
            NAT.DISABLED
            if self.public_address[0] == self.internal_address[0]
            else NAT.ENABLED
        )

    def facts_with(self, **kwargs):
        """Return a generator yielding facts which match the given properties. This is
        a relatively restrictive search and the properties must match exactly. For a more
        general search of facts, you can use a Python generator expression over the ``facts``
        list instead."""

        return (
            fact
            for fact in self.facts
            if all(getattr(fact, k, None) == v for k, v in kwargs.items())
        )
