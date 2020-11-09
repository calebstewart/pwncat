#!/usr/bin/env python3
import enum
import inspect
import pkgutil
from dataclasses import dataclass
import typing
from typing import Any, Callable
import typing
import fnmatch
import functools

from rich.progress import Progress

import pwncat
from pwncat.util import console

LOADED_MODULES = {}


class NoValue:
    """ Differentiates "None" from having no default value """


class ModuleNotFound(Exception):
    """ The specified module was not found """


class IncorrectPlatformError(Exception):
    """ The requested module didn't match the current platform """


class ArgumentFormatError(Exception):
    """ Format of one of the arguments was incorrect """


class MissingArgument(Exception):
    """ A required argument is missing """


class InvalidArgument(Exception):
    """ This argument does not exist and ALLOW_KWARGS was false """


class ModuleFailed(Exception):
    """ Base class for module failure """


class PersistError(ModuleFailed):
    """ Raised when any PersistModule method fails. """


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
    """ Argument information for a module """

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
    """ Argument list type, which accepts a list of the provided
    type. """

    def _ListType(value):
        if isinstance(value, list):
            return [_type(item) for item in value]
        return [_type(item) for item in value.split(",")]

    _ListType.__repr__ = lambda self: f"List[{_type}]"

    return _ListType


def Bool(value: str):
    """ Argument of type "bool". Accepts true/false (case-insensitive)
    as well as 1/0. The presence of an argument of type "Bool" with no
    assignment (e.g. run module arg) is equivalent to `run module arg=true`. """

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
    """ This is a module result. Modules can return standard python objects,
    but if they need to be formatted when displayed, each result should
    implement this interface. """

    @property
    def category(self) -> str:
        """ Return a "categry" of object. Categories will be grouped.
        If this returns None or is not defined, this result will be "uncategorized"
        """
        return None

    @property
    def title(self) -> str:
        """ Return a short-form description/title of the object. If not defined,
        this defaults to the object converted to a string. """
        raise NotImplementedError

    @property
    def description(self) -> str:
        """ Returns a long-form description. If not defined, the result is assumed
        to not be a long-form result. """
        return None

    def is_long_form(self) -> bool:
        """ Check if this is a long form result """
        try:
            if self.description is None:
                return False
        except NotImplementedError:
            return False
        return True

    def __str__(self) -> str:
        return self.title


class Status(str):
    """ A result which isn't actually returned, but simply updates
    the progress bar. It is equivalent to a string, so this is valid:
    ``yield Status("module status update")``"""


def run_decorator(real_run):
    """ Decorate a run function to evaluate types """

    @functools.wraps(real_run)
    def decorator(self, session, progress=None, **kwargs):

        if "exec" in kwargs:
            has_exec = True
        else:
            has_exec = False

        # Validate arguments
        for key in kwargs:
            if key in self.ARGUMENTS:
                try:
                    kwargs[key] = self.ARGUMENTS[key].type(kwargs[key])
                except ValueError:
                    raise ArgumentFormatError(key)
            elif not self.ALLOW_KWARGS:
                raise InvalidArgument(key)
        for key in self.ARGUMENTS:
            if key not in kwargs and key in pwncat.config:
                kwargs[key] = pwncat.config[key]
            elif key not in kwargs and self.ARGUMENTS[key].default is not NoValue:
                kwargs[key] = self.ARGUMENTS[key].default
            elif key not in kwargs and self.ARGUMENTS[key].default is NoValue:
                raise MissingArgument(key)

        # Save progress reference
        self.progress = progress

        # Return the result
        result_object = real_run(self, session, **kwargs)

        if inspect.isgenerator(result_object):

            try:
                if progress is None:
                    # We weren't given a progress instance, so start one ourselves
                    self.progress = Progress(
                        "collecting results",
                        "•",
                        "[yellow]{task.fields[module]}",
                        "•",
                        "[cyan]{task.fields[status]}",
                        transient=True,
                        console=console,
                    )
                    self.progress.start()

                # Added a task to this progress bar
                task = self.progress.add_task("", module=self.name, status="...")

                # Collect results
                results = []
                for item in result_object:
                    self.progress.update(task, status=str(item))
                    if not isinstance(item, Status):
                        results.append(item)

                if self.COLLAPSE_RESULT and len(results) == 1:
                    return results[0]

                return results
            finally:
                if progress is None:
                    # If we are the last task/this is our progress bar,
                    # we don't hide ourselves. This makes the progress bar
                    # empty, and "transient" ends up remove an extra line in
                    # the terminal.
                    self.progress.stop()
                else:
                    # This task is done, hide it.
                    self.progress.update(
                        task, completed=True, visible=False, status="complete"
                    )
        else:
            return result_object

    return decorator


class BaseModuleMeta(type):
    """ Ensures that type-checking is done on all "run" functions
    of sub-classes """

    def __new__(cls, name, bases, local):
        if "run" in local:
            local["run"] = run_decorator(local["run"])
        return super().__new__(cls, name, bases, local)


class BaseModule(metaclass=BaseModuleMeta):
    """ Generic module class. This class allows to easily create
    new modules. Any new module must inherit from this class. The
    run method is guaranteed to receive as key-word arguments any
    arguments specified in the ``ARGUMENTS`` dictionary. """

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
        """ The run method is called via keyword-arguments with all the
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


def reload(where: typing.Optional[typing.List[str]] = None):
    """ Reload modules from the given directory. If no directory
    is specified, then the default modules are reloaded. This
    function will not remove or un-load any existing modules, but
    may overwrite existing modules with conflicting names.

    :param where: Directories which contain pwncat modules
    :type where: List[str]
    """

    # We need to load built-in modules first
    if not LOADED_MODULES and where is not None:
        reload()

    # If no paths were specified, load built-ins
    if where is None:
        where = __path__

    for loader, module_name, _ in pkgutil.walk_packages(where, prefix=__name__ + "."):
        module = loader.find_module(module_name).load_module(module_name)

        if getattr(module, "Module", None) is None:
            continue

        module_name = module_name.split(__name__ + ".")[1]

        LOADED_MODULES[module_name] = module.Module()

        setattr(LOADED_MODULES[module_name], "name", module_name)


def find(name: str, base=BaseModule, ignore_platform: bool = False):
    """ Locate a module with this exact name. Optionally filter
    modules based on their class type. By default, this will search
    for any module implementing BaseModule which is applicable to
    the current platform.

    :param name: Name of the module to locate
    :type name: str
    :param base: Base class which the module must implement
    :type base: type
    :param ignore_platform: Whether to ignore the victim's platform in the search
    :type ignore_platform: bool
    :raises ModuleNotFoundError: Raised if the module does not exist or the platform/base class do not match.
    """

    if not LOADED_MODULES:
        reload()

    if name not in LOADED_MODULES:
        raise ModuleNotFoundError(f"{name}: module not found")

    if not isinstance(LOADED_MODULES[name], base):
        raise ModuleNotFoundError(f"{name}: incorrect base class")

    # Grab the module
    module = LOADED_MODULES[name]

    if not ignore_platform:
        if module.PLATFORM != Platform.NO_HOST and pwncat.victim.host is None:
            raise ModuleNotFoundError(f"{module.name}: no connected victim")
        elif (
            module.PLATFORM != Platform.NO_HOST
            and pwncat.victim.host.platform not in module.PLATFORM
        ):
            raise ModuleNotFoundError(f"{module.name}: incorrect platform")

    return module


def match(pattern: str, base=BaseModule):
    """ Locate modules who's name matches the given glob pattern.
    This function will only return modules which implement a subclass
    of the given base class and which are applicable to the current
    target's platform.

    :param pattern: A Unix glob-like pattern for the module name
    :type pattern: str
    :param base: The base class for modules you are looking for (defaults to BaseModule)
    :type base: type
    :return: A generator yielding module objects which at least implement ``base``
    :rtype: Generator[base, None, None]
    """

    if not LOADED_MODULES:
        reload()

    for module_name, module in LOADED_MODULES.items():

        # NOTE - this should be cleaned up. It's gross.
        if not isinstance(module, base):
            continue
        if module.PLATFORM != Platform.NO_HOST and pwncat.victim.host is None:
            continue
        elif (
            module.PLATFORM != Platform.NO_HOST
            and pwncat.victim.host.platform not in module.PLATFORM
        ):
            continue
        if not fnmatch.fnmatch(module_name, pattern):
            continue

        yield module


def run(name: str, **kwargs):
    """ Locate a module by name and execute it. The module can be of any
    type and is guaranteed to match the current platform. If no module can
    be found which matches those criteria, an exception is thrown.

    :param name: The name of the module to run
    :type name: str
    :param kwargs: Keyword arguments for the module
    :type kwargs: Dict[str, Any]
    :returns: The result from the module's ``run`` method.
    :raises ModuleNotFoundError: If no module with that name matches the required criteria
    """

    if not LOADED_MODULES:
        reload()

    if name not in LOADED_MODULES:
        raise ModuleNotFoundError(f"{name}: module not found")

    # Grab the module
    module = LOADED_MODULES[name]

    if module.PLATFORM != Platform.NO_HOST and pwncat.victim.host is None:
        raise ModuleNotFoundError(f"{module.name}: no connected victim")
    elif (
        module.PLATFORM != Platform.NO_HOST
        and pwncat.victim.host.platform not in module.PLATFORM
    ):
        raise ModuleNotFoundError(f"{module.name}: incorrect platform")

    return module.run(**kwargs)
