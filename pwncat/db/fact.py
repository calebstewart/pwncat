#!/usr/bin/env python3
from sqlalchemy import Column, Integer, ForeignKey, PickleType, UniqueConstraint, String
from sqlalchemy.orm import relationship

from pwncat.db.base import Base


class Fact(Base):
    """ Store enumerated facts. The pwncat.enumerate.Fact objects are pickled and
    stored in the "data" column. The enumerator is arbitrary, but allows for
    organizations based on the source enumerator. """

    __tablename__ = "facts"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("host.id"))
    host = relationship("Host", back_populates="facts")
    type = Column(String)
    source = Column(String)
    data = Column(PickleType)
    __table_args__ = (
        UniqueConstraint("type", "data", "host_id", name="_type_data_uc"),
    )
