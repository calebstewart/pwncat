#!/usr/bin/env python3
import pkgutil
from typing import Optional, Dict, Iterator
from colorama import Fore


class PersistenceError(Exception):
    """ Indicates a problem in adding/removing a persistence method """


class Persistence:
    def __init__(self):

        self.methods: Dict[str, "PersistenceMethod"] = {}

        for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
            method = loader.find_module(module_name).load_module(module_name).Method()
            self.methods[method.name] = method

    def install(self, name: str, user: Optional[str] = None):
        """ Add persistence as the specified user. If the specified persistence
        method is system method, the "user" argument is ignored. """
        method = self.find(name)
        if not method.system and user is None:
            raise PersistenceError("non-system methods require a user argument")
        method.install(user)

    def find(
        self,
        name: Optional[str] = None,
        user: Optional[str] = None,
        installed: bool = False,
        local: Optional[bool] = None,
        system: Optional[bool] = None,
    ) -> Iterator["PersistenceMethod"]:

        for method in self.methods.values():
            if name is not None and method.name != name:
                # not the requested method
                continue
            if installed:
                if user is not None or system is None or method.system == system:
                    if not method.installed(user):
                        continue
                else:
                    # the user was not specified and this module is not a
                    # system module. We can't check install state, so we
                    # err on the side of caution here.
                    continue
            if local is not None and method.local != local:
                continue
            # All checks passed. Yield the method.
            yield method

    def remove(self, name: str, user: Optional[str] = None):
        """ Remove the specified persistence method from the remote victim
        if the given persistence method is a system method, the "user"
        argument is ignored. """
        method = self.find(name)
        if not method.system and user is None:
            raise PersistenceError("non-system methods require a user argument")
        if not method.installed(user):
            raise PersistenceError("not installed")
        method.remove(user)

    def __iter__(self) -> Iterator["PersistenceMethod"]:
        yield from self.methods.values()


class PersistenceMethod:
    """ Base persistence method class """

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
        raise NotImplementedError

    def remove(self, user: Optional[str] = None):
        raise NotImplementedError

    def installed(self, user: Optional[str] = None) -> bool:
        raise NotImplementedError

    def escalate(self, user: Optional[str] = None) -> bool:
        """ If this is a local method, this should escalate to the given user if
        the persistence is installed for that user. Because we don't currently
        have access as the given user, `installed` is not checked prior to this
        call. As such, you should handle failures correctly. This method returns
        whether we successfully escalated. """
        raise NotImplementedError

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
