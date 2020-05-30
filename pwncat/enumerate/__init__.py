#!/usr/bin/env python3
import pkgutil
from typing import Generator, Callable, Any

import sqlalchemy
from sqlalchemy.ext.mutable import Mutable

import pwncat


class FactData(Mutable):
    def __str__(self):
        return "unknown"

    @property
    def description(self):
        return None

    def __getstate__(self):
        d = self.__dict__.copy()
        d.pop("_parents", None)
        return d


class Enumerate:
    """ Abstract fact enumeration class for the victim. This abstracts
    the process of enumerating different facts from the remote victim.
    Facts are identified by their type which is a string. For example,
    an enumerator may provide the "suid" type which enumerates SUID
    binaries. There may be multiple enumerators which provide the same
    type of facts.
    
    Enumerators are created by creating a module under pwncat/enumerate
    which must implement the following:
    
    * `provides` - a string which indicates the type of facts which this
        enumerator provides
    * `name` - a string which is a unique name for this enumerator
    * `enumerate` - a method which returns a generator yielding all known
        new facts for this enumerator.
    
    """

    def __init__(self):

        self.enumerators = {}
        self.load_package(__path__)

    def load_package(self, path: list):

        for loader, module_name, is_pkg in pkgutil.walk_packages(path):
            enumerator = loader.find_module(module_name).load_module(module_name)

            if is_pkg:
                continue

            provided_types = enumerator.provides

            # if we didn't specify a list, make it a list for consistency
            if not isinstance(provided_types, list):
                provided_types = [provided_types]

            for provides in provided_types:
                if provides not in self.enumerators:
                    self.enumerators[provides] = []
                self.enumerators[provides].append(enumerator)

    def iter(
        self,
        typ: str = None,
        filter: Callable[[pwncat.db.Fact], bool] = None,
        only_cached=False,
    ) -> Generator[pwncat.db.Fact, None, None]:
        """
        Iterate over facts of the given type. The optional filter argument provides a
        way to filter facts based on a lambda function.
        
        :param typ: the type of facts to return
        :param filter: a callable which takes a Fact and returns a boolean indicating
                whether to yield this fact.
        :return: Generator[Fact, None, None]
        """

        # Yield all known facts
        for fact in pwncat.victim.host.facts:
            if fact is None:
                continue
            if fact.data is None:
                continue
            if typ is not None and fact.type != typ:
                continue
            if filter is not None and not filter(fact):
                continue
            yield fact

        if only_cached or (typ is not None and typ not in self.enumerators):
            return

        for name, enumerators in self.enumerators.items():
            if typ is not None and not name.startswith(typ):
                continue
            for enumerator in enumerators:

                # Check if this enumerator has already run
                if not getattr(enumerator, "always_run", False):
                    dummy_name = enumerator.name
                    if enumerator.per_user:
                        # For per_user enumerators, we run enumerate once per user ID
                        dummy_name += f".{pwncat.victim.current_user.id}"

                    # A dummy value is added to the database to signify this enumerator ran
                    if self.exist(enumerator.provides, dummy_name):
                        continue

                for data in enumerator.enumerate():
                    fact = self.add_fact(name, data, enumerator.name)
                    if fact.data is None:
                        continue
                    if filter is not None and not filter(fact):
                        continue
                    yield fact

                # Add the dummy value. We do this after so that
                # if the generator was closed, this data will get
                # re-enumerated for the missing entries.
                if not getattr(enumerator, "always_run", False):
                    self.add_fact(enumerator.provides, None, dummy_name)

    def __iter__(self):
        """
        Iterate over all facts, regardless of the type.
        
        :return:
        """
        yield from self.iter()

    def first(self, typ: str) -> pwncat.db.Fact:
        """
        Find and return the first fact matching this type. Raises a ValueError
        if no fact of the given type exists/could be enumerated.

        :param typ: the fact type
        :return: the fact
        :raises: ValueError
        """

        try:
            iter = self.iter(typ)
            fact = next(iter)
            iter.close()
        except StopIteration:
            raise ValueError(f"{typ}: no facts located")

        return fact

    def add_fact(self, typ: str, data: Any, source: str) -> pwncat.db.Fact:
        """
        Register a fact with the fact database. This does not have to come from
        an enumerator. It likely didn't. This will be registered in the database
        and returned from `iter` after this.
        
        :param source: a printable description of what generated this fact
        :param typ: the type of fact
        :param data: type-specific data for this fact. this must be pickle-able
        """
        row = pwncat.db.Fact(
            host_id=pwncat.victim.host.id, type=typ, data=data, source=source,
        )
        try:
            pwncat.victim.session.add(row)
            pwncat.victim.session.commit()
            pwncat.victim.host.facts.append(row)
        except sqlalchemy.exc.IntegrityError:
            pwncat.victim.session.rollback()
            return (
                pwncat.victim.session.query(pwncat.db.Fact)
                .filter_by(host_id=pwncat.victim.host.id, type=typ, data=data)
                .first()
            )

        return row

    def flush(self, typ: str = None, provider: str = None, exact: bool = False):
        """
        Flush all facts provided by the given provider.
        
        :param provider:
        :return:
        """

        # Delete all matching facts
        for fact in pwncat.victim.host.facts:
            if typ is not None and exact and fact.type != typ:
                continue
            elif typ is not None and not exact and not fact.type.startswith(typ):
                continue
            if provider is not None and fact.source != provider:
                continue
            pwncat.victim.session.delete(fact)

        # Reload the host object
        pwncat.victim.session.commit()
        pwncat.victim.host = (
            pwncat.victim.session.query(pwncat.db.Host)
            .filter_by(id=pwncat.victim.host.id)
            .first()
        )

    def exist(self, typ: str, provider: str = None) -> bool:
        """
        Test whether any facts with the given type exist in the database.
        
        :param typ: the type of facts to look for
        :return: boolean, whether any facts exist for this type
        """

        for row in pwncat.victim.host.facts:
            if row.type == typ:
                if provider is not None and provider != row.source:
                    continue
                return True

        return False
