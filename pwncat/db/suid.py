#!/usr/bin/env python3
from sqlalchemy import ForeignKey, Integer, Column, String
from sqlalchemy.orm import relationship

from pwncat.db.base import Base


class SUID(Base):

    __tablename__ = "suid"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"))
    host = relationship("Host", back_populates="suid", foreign_keys=[host_id])
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # user = relationship("User", backref="suid", foreign_keys=[user_id])
    # Path to this SUID binary
    path = Column(String)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # owner = relationship("User", foreign_keys=[owner_id], backref="owned_suid")
