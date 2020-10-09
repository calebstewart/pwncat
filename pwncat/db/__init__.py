#!/usr/bin/env python3

from sqlalchemy.engine import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

import pwncat
from pwncat.db.base import Base
from pwncat.db.binary import Binary
from pwncat.db.history import History
from pwncat.db.host import Host
from pwncat.db.persist import Persistence
from pwncat.db.suid import SUID
from pwncat.db.tamper import Tamper
from pwncat.db.user import User, Group, SecondaryGroupAssociation
from pwncat.db.fact import Fact

ENGINE: Engine = None
SESSION_MAKER = None
SESSION: Session = None


def get_engine() -> Engine:
    """
    Get a copy of the database engine
    """

    global ENGINE

    if ENGINE is not None:
        return ENGINE

    ENGINE = create_engine(pwncat.config["db"], echo=False)
    Base.metadata.create_all(ENGINE)

    return ENGINE


def get_session() -> Session:
    """
    Get a new session object
    """

    global SESSION_MAKER
    global SESSION

    if SESSION_MAKER is None:
        SESSION_MAKER = sessionmaker(bind=get_engine())
    if SESSION is None:
        SESSION = SESSION_MAKER()

    return SESSION


def reset_engine():
    """
    Reload the engine and session
    """

    global ENGINE
    global SESSION
    global SESSION_MAKER

    ENGINE = None
    SESSION = None
    SESSION_MAKER = None
