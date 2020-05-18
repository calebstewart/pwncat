#!/usr/bin/env python3
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from pwncat.db.base import Base


class Persistence(Base):

    __tablename__ = "persistence"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"))
    host = relationship("Host", back_populates="persistence")
    # The type of persistence
    method = Column(String)
    # The user this persistence was applied as (ignored for system persistence)
    user = Column(String)
