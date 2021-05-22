#!/usr/bin/env python3
import enum
import typing
import fnmatch
import inspect
import pkgutil
import functools
from typing import Any, Callable
from dataclasses import dataclass

import pwncat
from pwncat.util import console
from rich.progress import Progress

LOADED_MODULES = {}


class NoValue:
    """Differentiates "None" from having no default value"""


class ModuleNotFound(Exception):
    """The specified module was not found"""


class IncorrectPlatformError(Exception):
    """The requested module didn't match the current platform"""


class ArgumentFormatError(Exception):
    """Format of one of the arguments was incorrect"""


class MissingArgument(Exception):
    """A required argument is missing"""


class InvalidArgument(Exception):
    """This argument does not exist and ALLOW_KWARGS was false"""


class ModuleFailed(Exception):
    """Base class for module failure"""


class PersistError(ModuleFailed):
    """Raised when any PersistModule method fails."""


class PersistType(enum.Flag):
    """
    Identifies the persistence module type flags. One or more flags
    must be specified for a module.
    """

    LOCAL = enum.auto()
    """ The persistence module implements the ``escalate`` method for
    local privilege escalation. """
    REMOTE = enum.auto()
    """ The persistence module implements the ``connect`` method for
    remote connection. """
    ALL_USERS = enum.auto()
    """ When installed, the persistence module allows access as any
    user. """


@dataclass
class Argument:
    """Argument information for a module"""

    type: Callable[[str], Any] = str
    """ A callable which converts a string to the required type
    This function should also return the passed value if it is
    already of that type. """
    default: Any = NoValue
    """ The default value if none is specified in ``run``. If this
    is ``NoValue``, then the argument is required. """
    help: str = ""
    """ The help text displayed in the ``info`` output. """


def List(_type=str):
    """Argument list type, which accepts a list of the provided
    type."""

    def _ListType(value):
        if isinstance(value, list):
            return [_type(item) for item in value]
        return [_type(item) for item in value.split(",")]

    _ListType.__repr__ = lambda self: f"List[{_type}]"

    return _ListType


def Bool(value: str):
    """Argument of type "bool". Accepts true/false (case-insensitive)
    as well as 1/0. The presence of an argument of type "Bool" with no
    assignment (e.g. run module arg) is equivalent to `run module arg=true`."""

    if isinstance(value, bool):
        return value

    if not isinstance(value, str):
        return bool(value)

    if value.lower() == "true" or value == "1":
        return True
    elif value.lower() == "false" or value == "0":
        return False

    raise ValueError(f"invalid boolean value: {value}")


class Result:
    """This is a module result. Modules can return standard python objects,
    but if they need to be formatted when displayed, each result should
    implement this interface."""

    def category(self, session) -> str:
        """Return a "category" of object. Categories will be grouped.
        If this returns None or is not defined, this result will be "uncategorized"
        """
        return None

    def title(self, session) -> str:
        """Return a short-form description/title of the object. If not defined,
        this defaults to the object converted to a string."""
        return str(self)

    def description(self, session) -> str:
        """Returns a long-form description. If not defined, the result is assumed
        to not be a long-form result."""
        return None

    def is_long_form(self, session) -> bool:
        """Check if this is a long form result"""
        try:
            if self.description(session) is None:
                return False
        except NotImplementedError:
            return False
        return True


class Status(str):
    """A result which isn't actually returned, but simply updates
    the progress bar. It is equivalent to a string, so this is valid:
    ``yield Status("module status update")``"""

    def category(self, session) -> str:
        """Return a "category" of object. Categories will be grouped.
        If this returns None or is not defined, this result will be "uncategorized"
        """
        return None

    def title(self, session) -> str:
        """Return a short-form description/title of the object. If not defined,
        this defaults to the object converted to a string."""
        return str(self)

    def description(self, session) -> str:
        """Returns a long-form description. If not defined, the result is assumed
        to not be a long-form result."""
        return None

    def is_long_form(self, session) -> bool:
        """Check if this is a long form result"""
        try:
            if self.description(session) is None:
                return False
        except NotImplementedError:
            return False
        return True


def run_decorator(real_run):
    """Decorate a run function to evaluate types"""

    @functools.wraps(real_run)
    def decorator(self, session, progress=None, **kwargs):

        # Validate arguments
        for key in kwargs:
            if key in self.ARGUMENTS:
                try:
                    kwargs[key] = self.ARGUMENTS[key].type(kwargs[key])
                except ValueError as exc:
                    raise ArgumentFormatError(key) from exc
            elif not self.ALLOW_KWARGS:
                raise InvalidArgument(key)
        for key in self.ARGUMENTS:
            if key not in kwargs and key in session.config:
                kwargs[key] = session.config[key]
            elif key not in kwargs and self.ARGUMENTS[key].default is not NoValue:
                kwargs[key] = self.ARGUMENTS[key].default
            elif key not in kwargs and self.ARGUMENTS[key].default is NoValue:
                raise MissingArgument(key)

        # Ensure that our database connection is up to date
        if session.module_depth == 0:
            # pwncat.console.log("incrementing mod counter")
            session.db.transaction_manager.begin()
        session.module_depth += 1
        old_show_progress = session.showing_progress
        if progress is not None:
            session.showing_progress = progress

        try:

            # Return the result
            result_object = real_run(self, session, **kwargs)

            if inspect.isgenerator(result_object):
                if session.showing_progress:
                    with session.task(description=self.name, status="...") as task:
                        # Collect results
                        results = []
                        for item in result_object:
                            session.update_task(task, status=item.title(session))
                            if not isinstance(item, Status):
                                results.append(item)
                else:
                    results = [
                        item for item in result_object if not isinstance(item, Status)
                    ]

                if self.COLLAPSE_RESULT and len(results) == 1:
                    return results[0]

                return results
            else:
                return result_object
        finally:
            session.module_depth -= 1
            session.showing_progress = old_show_progress

            if session.module_depth == 0:
                session.db.transaction_manager.commit()

    return decorator


class BaseModuleMeta(type):
    """Ensures that type-checking is done on all "run" functions
    of sub-classes"""

    def __new__(cls, name, bases, local):
        if "run" in local:
            local["run"] = run_decorator(local["run"])
        return super().__new__(cls, name, bases, local)


class BaseModule(metaclass=BaseModuleMeta):
    """Generic module class. This class allows to easily create
    new modules. Any new module must inherit from this class. The
    run method is guaranteed to receive as key-word arguments any
    arguments specified in the ``ARGUMENTS`` dictionary."""

    ARGUMENTS = {
        # "name": Argument(int, default="value"),
        # "name2": Argument(List(int), default=[1, 2, 3]),
    }
    """ Arguments which can be provided to the ``run`` method.
    This maps argument names to ``Argument`` instances describing
    the type, default value, and requirements for an individual
    argument.
    """
    ALLOW_KWARGS = False
    """ Allow other kwargs parameters outside of what is specified by
    the arguments dictionary. This allows arbitrary arguments which
    are not type-checked to be passed. You should use `**kwargs` in
    your run method if this is set to True. """
    COLLAPSE_RESULT = False
    """ If you want to use `yield Status(...)` to update the progress bar
    but only return one scalar value, setting this to true will collapse
    an array with only a single object to it's scalar value. """
    PLATFORM: typing.List[typing.Type["pwncat.platform.Platform"]] = []
    """ The platform this module is compatibile with (can be multiple) """

    def __init__(self):
        self.progress = None
        # Filled in by reload
        self.name = None

    def run(self, session, progress=None, **kwargs):
        """The run method is called via keyword-arguments with all the
        parameters specified in the ``ARGUMENTS`` dictionary. If ``ALLOW_KWARGS``
        was True, then other keyword arguments may also be passed. Any
        types specified in ``ARGUMENTS`` will already have been checked.

        If there are any errors while processing a module, the module should
        raise ``ModuleError`` or a subclass in order to enable ``pwncat`` to
        automatically and gracefully handle a failed module execution.

        :param progress: A python-rich Progress instance
        :type progress: rich.progress.Progress
        """

        raise NotImplementedError
