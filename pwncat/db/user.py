#!/usr/bin/env python3
from sqlalchemy import Column, Integer, String, ForeignKey, Table
from sqlalchemy.orm import relationship

from pwncat.db.base import Base

SecondaryGroupAssociation = Table(
    "secondary_group_association",
    Base.metadata,
    Column("group_id", Integer, ForeignKey("groups.id")),
    Column("user_id", ForeignKey("users.id")),
)


class Group(Base):

    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"), primary_key=True)
    host = relationship("Host", back_populates="groups")
    name = Column(String)
    members = relationship(
        "User",
        back_populates="groups",
        secondary=SecondaryGroupAssociation,
        lazy="selectin",
    )

    def __repr__(self):
        return f"""Group(gid={self.id}, name={repr(self.name)}), members={repr(",".join(m.name for m in self.members))})"""


class User(Base):

    __tablename__ = "users"

    # The users UID
    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"), primary_key=True)
    host = relationship("Host", back_populates="users", lazy="selectin")
    # The users GID
    gid = Column(Integer, ForeignKey("groups.id"))
    # The actual DB Group object representing that group
    group = relationship("Group")
    # The name of the user
    name = Column(String, primary_key=True)
    # The user's full name
    fullname = Column(String)
    # The user's home directory
    homedir = Column(String)
    # The user's password, if known
    password = Column(String)
    # The hash of the user's password, if known
    hash = Column(String)
    # The user's default shell
    shell = Column(String)
    # The user's secondary groups
    groups = relationship(
        "Group",
        back_populates="members",
        secondary=SecondaryGroupAssociation,
        lazy="selectin",
    )

    def __repr__(self):
        return f"""User(uid={self.id}, gid={self.gid}, name={repr(self.name)})"""
