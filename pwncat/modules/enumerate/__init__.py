#!/usr/bin/env python3
from enum import Enum, auto
import fnmatch
import time

import sqlalchemy

import pwncat
from pwncat.platform import Platform
from pwncat.modules import BaseModule, Status, Argument, List
from pwncat.db import get_session


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
    PLATFORM = Platform.LINUX

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

    def run(self, types, clear):
        """ Locate all facts this module provides.

        Sub-classes should not override this method. Instead, use the
        enumerate method. `run` will cross-reference with database and
        ensure enumeration modules aren't re-run.
        """

        marker_name = self.name
        if self.SCHEDULE == Schedule.PER_USER:
            marker_name += f".{pwncat.victim.current_user.id}"

        if clear:
            # Delete enumerated facts
            query = (
                get_session()
                .query(pwncat.db.Fact)
                .filter_by(source=self.name, host_id=pwncat.victim.host.id)
            )
            query.delete(synchronize_session=False)
            # Delete our marker
            if self.SCHEDULE != Schedule.ALWAYS:
                query = (
                    get_session()
                    .query(pwncat.db.Fact)
                    .filter_by(host_id=pwncat.victim.host.id, type="marker")
                    .filter(pwncat.db.Fact.source.startswith(self.name))
                )
                query.delete(synchronize_session=False)
            return

        # Yield all the know facts which have already been enumerated
        existing_facts = (
            get_session()
            .query(pwncat.db.Fact)
            .filter_by(source=self.name, host_id=pwncat.victim.host.id)
            .filter(pwncat.db.Fact.type != "marker")
        )

        if types:
            for fact in existing_facts.all():
                for typ in types:
                    if fnmatch.fnmatch(fact.type, typ):
                        yield fact
        else:
            yield from existing_facts.all()

        if self.SCHEDULE != Schedule.ALWAYS:
            exists = (
                get_session()
                .query(pwncat.db.Fact.id)
                .filter_by(
                    host_id=pwncat.victim.host.id, type="marker", source=marker_name
                )
                .scalar()
                is not None
            )
            if exists:
                return

        # Get any new facts
        for item in self.enumerate():
            if isinstance(item, Status):
                yield item
                continue

            typ, data = item

            row = pwncat.db.Fact(
                host_id=pwncat.victim.host.id, type=typ, data=data, source=self.name
            )
            try:
                get_session().add(row)
                pwncat.victim.host.facts.append(row)
                get_session().commit()
            except sqlalchemy.exc.IntegrityError:
                get_session().rollback()
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
                host_id=pwncat.victim.host.id,
                type="marker",
                source=marker_name,
                data=None,
            )
            get_session().add(row)
            pwncat.victim.host.facts.append(row)

    def enumerate(self):
        """ Defined by sub-classes to do the actual enumeration of
        facts. """


# This makes `run enumerate` initiate a quick scan
from pwncat.modules.enumerate.quick import Module
