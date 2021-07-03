#!/usr/bin/env python3
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from pwncat.db.base import Base


class Binary(Base):

    __tablename__ = "binary"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"))
    host = relationship("Host", back_populates="binaries")
    # Name of the binary (parameter to which)
    name = Column(String)
    # The path to the binary on the remote host
    path = Column(String)
