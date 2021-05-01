#!/usr/bin/env python3
from enum import Enum, auto
import fnmatch
import time

# import sqlalchemy

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules import BaseModule, Status, Argument, List
from pwncat.db import get_session


class Schedule(Enum):
    """Defines how often an enumeration module will run"""

    ALWAYS = auto()
    PER_USER = auto()
    ONCE = auto()


class EnumerateModule(BaseModule):
    """Base class for all enumeration modules"""

    # List of categories/enumeration types this module provides
    # This should be set by the sub-classes to know where to find
    # different types of enumeration data
    PROVIDES = []
    PLATFORM = []

    # Defines how often to run this enumeration. The default is to
    # only run once per system/target.
    SCHEDULE = Schedule.ONCE

    # Arguments which all enumeration modules should take
    # This shouldn't be modified. Enumeration modules don't take any
    # parameters
    ARGUMENTS = {
        "types": Argument(
            List(str),
            default=[],
            help="A list of enumeration types to retrieve (default: all)",
        ),
        "clear": Argument(
            bool,
            default=False,
            help="If specified, do not perform enumeration. Cleared cached results.",
        ),
    }

    def run(self, session, types, clear):
        """Locate all facts this module provides.

        Sub-classes should not override this method. Instead, use the
        enumerate method. `run` will cross-reference with database and
        ensure enumeration modules aren't re-run.
        """

        marker_name = self.name
        if self.SCHEDULE == Schedule.PER_USER:
            marker_name += f".{session.platform.current_user().id}"

        with session.db as db:

            if clear:
                # Delete enumerated facts
                session.target.facts = persistent.list.PersistentList(
                    (f for f in session.target.facts if f.source != self.name)
                )

                # Delete our marker
                #### We aren't positive how to recreate this in ZODB yet
                # if self.SCHEDULE != Schedule.ALWAYS:
                #     query = (
                #         db.query(pwncat.db.Fact)
                #         .filter_by(host_id=session.host, type="marker")
                #         .filter(pwncat.db.Fact.source.startswith(self.name))
                #     )
                #     query.delete(synchronize_session=False)
                return

            # Yield all the know facts which have already been enumerated
            existing_facts = (f for f in session.target.facts if f.source == self.name)

            if types:
                for fact in existing_facts:
                    for typ in types:
                        if fnmatch.fnmatch(fact.type, typ):
                            yield fact
            else:
                yield from existing_facts

            if self.SCHEDULE != Schedule.ALWAYS:
                exists = (
                    db.query(pwncat.db.Fact.id)
                    .filter_by(host_id=session.host, type="marker", source=marker_name)
                    .scalar()
                    is not None
                )
                if exists:
                    return

            # Get any new facts
            for item in self.enumerate(session):
                if isinstance(item, Status):
                    yield item
                    continue

                typ, data = item
                # session.target.facts.append(fact)

                # row = pwncat.db.Fact(
                #     host_id=session.host, type=typ, data=data, source=self.name
                # )
                try:
                    db.add(row)
                    db.commit()
                except sqlalchemy.exc.IntegrityError:
                    db.rollback()
                    yield Status(data)
                    continue

                # Don't yield the actual fact if we didn't ask for this type
                if types:
                    for typ in types:
                        if fnmatch.fnmatch(row.type, typ):
                            yield row
                        else:
                            yield Status(data)
                else:
                    yield row

            # Add the marker if needed
            if self.SCHEDULE != Schedule.ALWAYS:
                row = pwncat.db.Fact(
                    host_id=session.host,
                    type="marker",
                    source=marker_name,
                    data=None,
                )
                db.add(row)
            # session.db.transaction_manager.commit()

    def enumerate(self, session):
        """
        Defined by sub-classes to do the actual enumeration of
        facts.
        """


# This makes `run enumerate` initiate a quick scan
from pwncat.modules.enumerate.quick import Module
