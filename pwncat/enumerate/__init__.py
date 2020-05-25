#!/usr/bin/env python3
import pkgutil
from typing import Generator, Callable, Any

import sqlalchemy

import pwncat


class Fact:
    """
    I don't know how to generically represent this yet...
    """


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
        for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
            enumerator = loader.find_module(module_name).load_module(module_name)
            if enumerator.provides not in self.enumerators:
                self.enumerators[enumerator.provides] = []
            self.enumerators[enumerator.provides].append(enumerator)

    def iter(
        self, typ: str = None, filter: Callable[[Fact], bool] = None, only_cached=False
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
            if fact.data is None:
                continue
            if typ is not None and fact.type != typ:
                continue
            if filter is not None and not filter(fact):
                continue
            yield fact

        if only_cached or (typ is not None and typ not in self.enumerators):
            return

        # If we know of enumerators for this type of fact, we check with them for
        # any new matching facts.
        if typ is not None:
            for enumerator in self.enumerators[typ]:
                for data in enumerator.enumerate():
                    fact = self.add_fact(typ, data, enumerator.name)
                    if fact.data is None:
                        continue
                    if filter is not None and not filter(fact):
                        continue
                    yield fact
        else:
            for typ, enumerators in self.enumerators.items():
                for enumerator in enumerators:
                    for data in enumerator.enumerate():
                        fact = self.add_fact(typ, data, enumerator.name)
                        if fact.data is None:
                            continue
                        if filter is not None and not filter(fact):
                            continue
                        yield fact

    def __iter__(self):
        """
        Iterate over all facts, regardless of the type.
        
        :return:
        """
        yield from self.iter()

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

    def flush(self, typ: str = None, provider: str = None):
        """
        Flush all facts provided by the given provider.
        
        :param provider:
        :return:
        """

        # Delete all matching facts
        for fact in pwncat.victim.host.facts:
            if typ is not None and fact.type != typ:
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
