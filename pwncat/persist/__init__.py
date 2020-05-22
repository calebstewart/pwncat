#!/usr/bin/env python3
import functools
import pkgutil
import socket
from typing import Optional, Dict, Iterator, Tuple
from colorama import Fore

import pwncat
from pwncat.tamper import RevertFailed


class PersistenceError(Exception):
    """ Indicates a problem in adding/removing a persistence method """


def persistence_tamper_removal(name: str, user: Optional[str] = None):
    try:
        pwncat.victim.persist.remove(name, user, from_tamper=True)
    except PersistenceError as exc:
        raise RevertFailed(str(exc))


class Persistence:
    """
    This class abstracts the management of persistence methods and is accessible at runtime
    via ``pwncat.victim.persist``. It provides methods of enumerating available persistence
    methods, enumerating installed persistence methods, installing methods, and removing
    methods.
    """

    def __init__(self):

        self.methods: Dict[str, "PersistenceMethod"] = {}

        for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
            method = loader.find_module(module_name).load_module(module_name).Method()
            self.methods[method.name] = method

    def install(self, name: str, user: Optional[str] = None):
        """
        Install the specified method by name. If the specified method is not a system
        method, ``user`` specifies the user to install this method as. Otherwise, the
        ``user`` parameter is ignored.
        
        This method raises a PersistenceError if installation failed or the given method
        does not exist.
        
        :param name: the name of the persistence method to install
        :param user: the user to install persistence as
        """
        try:
            method = next(self.find(name))
        except StopIteration:
            raise PersistenceError(f"{name}: no such persistence method")
        if not method.system and user is None:
            raise PersistenceError(
                f"{method.format(user)}: non-system methods require a user argument"
            )
        if method.installed(user):
            raise PersistenceError(f"{method.format(user)}: already installed")
        if method.system and user is not None:
            user = None
        method.install(user)
        self.register(name, user)

    def register(self, name: str, user: Optional[str] = None):
        """
        Register a persistence method as pre-installed. This is useful for some privilege escalation
        which automatically adds things equivalent to persistent, but without the
        persistence module itself (e.g. backdooring /etc/passwd or SSH keys).
        
        This method raises a PersistenceError if the given persistence method
        does not exist.
        
        :param name: the method to register as pre-installed
        :param user: the user the method was installed as
        """

        method = next(self.find(name))

        persist = pwncat.db.Persistence(method=name, user=user)
        pwncat.victim.host.persistence.append(persist)

        # Also register a tamper to track in both places
        pwncat.victim.tamper.custom(
            f"Persistence: {method.format(user)}",
            functools.partial(persistence_tamper_removal, name=name, user=user),
        )

    @property
    def installed(self) -> Iterator[Tuple[str, "PersistenceMethod"]]:
        """
        Enumerate all installed persistence methods.
        
        :return: An iterator of tuples of (username,PeristenceMethod)
        """
        for persist in pwncat.victim.host.persistence:
            yield persist.user, self.methods[persist.method]

    @property
    def available(self) -> Iterator["PersistenceMethod"]:
        """
        Enumerate all available persistence methods
        
        :return: Iterator of available persistence methods
        """
        yield from self.methods.values()

    def find(self, name: Optional[str] = None,) -> Iterator["PersistenceMethod"]:
        """
        Locate persistence methods matching the given name.
        
        :param name: the name of the persistence module to locate
        :return: Iterator of persistence methods matching the name
        """
        for method in self.methods.values():
            if name is not None and method.name != name:
                # not the requested method
                continue
            # All checks passed. Yield the method.
            yield method

    def remove(self, name: str, user: Optional[str] = None, from_tamper: bool = False):
        """
        Remove the specified persistence method from the remote victim
        if the given persistence method is a system method, the "user"
        argument is ignored.
        
        Raises a ``PersistenceError`` if the given method doesn't exist or removal
        failed.
        
        The ``from_tamper`` parameter should not be used and is only used
        for internal removal from within the tamper subsystem.
        
        :param name: the name of the method to remove
        :param user: the user which was used to install this method
        :param from_tamper: whether we are removing from the tamper removal system
        """
        try:
            method = next(self.find(name))
        except StopIteration:
            raise PersistenceError(f"{name}: no such persistence method")
        if not method.system and user is None:
            raise PersistenceError(
                f"{method.format(user)}: non-system methods require a user argument"
            )
        if method.system and user is not None:
            user = None
        if not method.installed(user):
            raise PersistenceError(f"{method.format(user)}: not installed")
        method.remove(user)

        # Grab this from the database
        persist = (
            pwncat.victim.session.query(pwncat.db.Persistence)
            .filter_by(host_id=pwncat.victim.host.id, method=name, user=user)
            .first()
        )
        if persist is not None:
            pwncat.victim.session.delete(persist)
            pwncat.victim.session.commit()

        # Remove the tamper as well
        if not from_tamper:
            for tamper in pwncat.victim.tamper:
                if str(tamper) == f"Persistence: {method.format(user)}":
                    pwncat.victim.tamper.remove(tamper)
                    break

    def __iter__(self) -> Iterator["PersistenceMethod"]:
        yield from self.methods.values()


class PersistenceMethod:
    """ Base persistence method class. The docstring for your method class will
    become the long-form help for this method (viewable with ``persist -l -m {method-name}``)
    """

    def __init__(self):
        pass

    @property
    def name(self) -> str:
        """ The printable name for this persistence method. Can be redefined
        from a property to a variable within the object. """
        raise NotImplementedError

    @property
    def system(self) -> bool:
        """ Whether this is a system method (and therefore doesn't need a user
        parameter) """
        raise NotImplementedError

    @property
    def local(self) -> bool:
        """ Does this provide local persistence? If so, we can use it to
        escalate with local access """
        raise NotImplementedError

    def install(self, user: Optional[str] = None):
        """
        Install this method of persistence as the given user. Raise a
        ``PersistenceError`` if installation fails.
        
        :param user: the user to install persistence as
        """
        raise NotImplementedError

    def remove(self, user: Optional[str] = None):
        """
        Remove this method of persistence as the given user. Raise a
        ``PersistenceError`` if removal fails.
        
        :param user: the user to remove persistence as
        """
        raise NotImplementedError

    def installed(self, user: Optional[str] = None) -> bool:
        if (
            pwncat.victim.session.query(pwncat.db.Persistence)
            .filter_by(method=self.name, user=user)
            .first()
            is not None
        ):
            return True
        return False

    def escalate(self, user: Optional[str] = None) -> bool:
        """ If this is a local method, this should escalate to the given user if
        the persistence is installed for that user. Because we don't currently
        have access as the given user, `installed` is not checked prior to this
        call. As such, you should handle failures correctly. This method returns
        whether we successfully escalated. """
        raise NotImplementedError

    def reconnect(self, user: Optional[str] = None) -> socket.SocketType:
        """
        Reconnect to the remote victim using this persistence method. In this case,
        the ``pwncat.victim`` object is partially initialized. The database is
        loaded, and the ``pwncat.victim.host`` object is accessible, however no
        connection to the remote victim has been established. This function should
        utilize the installed persistence to initiate a remote connection to the
        target. If the connection fails, a PersistenceError is raised. If the
        connection succeeds, you should return an open socket-like object which is
        used to communicate with the remote shell.
        
        :param user: the user to connect as (ignored for system methods)
        :return: socket-like object connected to the remote shell's stdio
        """
        raise PersistenceError("remote initiation not possible")

    def format(self, user: Optional[str] = None):
        """ Format the name and user into a printable display name """
        if self.system:
            result = (
                f"{Fore.CYAN}{self.name}{Fore.RESET} as {Fore.RED}system{Fore.RESET}"
            )
        else:
            if user is None:
                user = "user"
            result = (
                f"{Fore.CYAN}{self.name}{Fore.RESET} as {Fore.GREEN}{user}{Fore.RESET}"
            )
        if self.local:
            result = f"{result} ({Fore.MAGENTA}local{Fore.RESET})"
        return result
