#!/usr/bin/env python3
from enum import Enum, auto

import sqlalchemy

import pwncat
from pwncat.modules import BaseModule, Status, Argument, List


class Schedule(Enum):
    """ Defines how often an enumeration module will run """

    ALWAYS = auto()
    PER_USER = auto()
    ONCE = auto()


class EnumerateModule(BaseModule):
    """ Base class for all enumeration modules """

    # List of categories/enumeration types this module provides
    # This should be set by the sub-classes to know where to find
    # different types of enumeration data
    PROVIDES = []

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
        )
    }

    def run(self, types):
        """ Locate all facts this module provides.

        Sub-classes should not override this method. Instead, use the
        enumerate method. `run` will cross-reference with database and
        ensure enumeration modules aren't re-run.
        """

        # Yield all the know facts which have already been enumerated
        existing_facts = (
            pwncat.victim.session.query(pwncat.db.Fact)
            .filter_by(source=self.name)
            .filter(pwncat.db.Fact.type != "marker")
        )

        if types:
            existing_facts = existing_facts.filter(pwncat.db.Fact.type.in_(types))

        yield from existing_facts.all()

        marker_name = None

        if self.SCHEDULE != Schedule.ALWAYS:
            marker_name = self.name
            if self.SCHEDULE == Schedule.PER_USER:
                marker_name += f".{pwncat.victim.current_user.id}"

            exists = (
                pwncat.victim.session.query(pwncat.db.Fact.id)
                .filter_by(type="marker", source=marker_name)
                .scalar()
                is not None
            )
            if exists:
                return

        # Get any new facts
        for typ, data in self.enumerate():
            row = pwncat.db.Fact(
                host_id=pwncat.victim.host.id, type=typ, data=data, source=self.name
            )
            try:
                pwncat.victim.session.add(row)
                pwncat.victim.host.facts.append(row)
                pwncat.victim.session.commit()
            except sqlalchemy.exc.IntegrityError:
                pwncat.victim.session.rollback()
                yield Status(data)
                continue

            # Don't yield the actual fact if we didn't ask for this type
            if types and row.type not in types:
                yield Status(data)
            else:
                yield row

        # Add the marker if needed
        if self.SCHEDULE != Schedule.ALWAYS:
            row = pwncat.db.Fact(
                host_id=pwncat.victim.host.id,
                type="marker",
                source=marker_name,
                data=None,
            )
            pwncat.victim.session.add(row)
            pwncat.victim.host.facts.append(row)

    def enumerate(self):
        """ Defined by sub-classes to do the actual enumeration of
        facts. """


# This makes `run enumerate` initiate a quick scan
from pwncat.modules.enumerate.quick import Module
