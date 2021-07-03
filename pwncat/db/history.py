#!/usr/bin/env python3
from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship

from pwncat.db.base import Base


class History(Base):

    __tablename__ = "history"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"))
    host = relationship("Host", back_populates="history")
    command = Column(String)
