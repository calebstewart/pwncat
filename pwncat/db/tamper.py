#!/usr/bin/env python3
from sqlalchemy import Column, Integer, String, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship

from pwncat.db.base import Base


class Tamper(Base):

    __tablename__ = "tamper"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"))
    host = relationship("Host", back_populates="tampers")
    name = Column(String)
    data = Column(LargeBinary)
