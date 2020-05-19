#!/usr/bin/env python3
from sqlalchemy import Column, Integer, String, Enum, Boolean
from sqlalchemy.orm import relationship

from pwncat import util
from pwncat.db.base import Base


class Host(Base):

    __tablename__ = "host"

    # Database identifier
    id = Column(Integer, primary_key=True)
    # A unique hash identifying this host
    hash = Column(String)
    # The remote architecture (uname -m)
    arch = Column(String)
    # The remote init system being used
    init = Column(Enum(util.Init))
    # The remote kernel version (uname -r)
    kernel = Column(String)
    # The remote distro (probed from /etc/*release), or "unknown"
    distro = Column(String)
    # The path to the remote busybox, if installed
    busybox = Column(String)
    # Did we install busybox?
    busybox_uploaded = Column(Boolean)
    # A list of groups this host has
    groups = relationship("Group")
    # A list of users this host has
    users = relationship("User")
    # A list of persistence methods applied to this host
    persistence = relationship("Persistence")
    # A list of tampers applied to this host
    tampers = relationship("Tamper")
    # A list of resolved binaries for the remote host
    binaries = relationship("Binary")
    # Command history for local prompt
    history = relationship("History")
    # A list of SUID binaries found across all users (may have overlap, and may not be
    # accessible by the current user).
    suid = relationship("SUID")
