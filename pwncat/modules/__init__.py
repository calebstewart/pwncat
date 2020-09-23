#!/usr/bin/env python3
import inspect
import pkgutil
import re
from dataclasses import dataclass
import typing
from typing import Any, Callable

from rich.progress import Progress

import pwncat
from pwncat.platform import Platform
from pwncat.util import console

LOADED_MODULES = {}


class NoValue:
    """ Differentiates "None" from having no default value """


class ModuleNotFound(Exception):
    """ The specified module was not found """


class ArgumentFormatError(Exception):
    """ Format of one of the arguments was incorrect """


class MissingArgument(Exception):
    """ A required argument is missing """


class InvalidArgument(Exception):
    """ This argument does not exist and ALLOW_KWARGS was false """


class ModuleFailed(Exception):
    """ Base class for module failure """


@dataclass
class Argument:
    """ Argument information for a module """

    type: Callable[[str], Any] = str
    default: Any = NoValue
    help: str = ""


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
        """ Return a "categry" of object. Categories will be grouped. """
        return None

    @property
    def title(self) -> str:
        """ Return a short-form description/title of the object """
        raise NotImplementedError

    @property
    def description(self) -> str:
        """ Returns a long-form description """
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
    the progress bar. """


def run_decorator(real_run):
    """ Decorate a run function to evaluate types """

    def decorator(self, progress=None, **kwargs):

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
            if key not in kwargs and key in pwncat.victim.config:
                kwargs[key] = pwncat.victim.config[key]
            elif key not in kwargs and self.ARGUMENTS[key].default is not NoValue:
                kwargs[key] = self.ARGUMENTS[key].default
            elif key not in kwargs and self.ARGUMENTS[key].default is NoValue:
                raise MissingArgument(key)

        # Save progress reference
        self.progress = progress

        # Return the result
        result_object = real_run(self, **kwargs)

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
    """ Generic module class """

    ARGUMENTS = {
        # "name": Argument(int, default="value"),
        # "name2": Argument(List(int), default=[1, 2, 3]),
    }
    # Allow other kwargs parameters outside of what is specified by
    # the arguments dictionary. This allows arbitrary arguments which
    # are not type-checked to be passed. You should use `**kwargs` in
    # your run method.
    ALLOW_KWARGS = False
    # If you want to use `yield Status(...)` to update the progress bar
    # but only return one scalar value, setting this to true will collapse
    # an array with only a single object to it's scalar value.
    COLLAPSE_RESULT = False
    # The platform which this module is for
    PLATFORM = Platform.UNKNOWN

    def __init__(self):
        self.progress = None
        # Filled in by reload
        self.name = None

    def run(self, **kwargs):
        """ Execute this module """
        raise NotImplementedError


def reload(where: typing.Optional[typing.List[str]] = None):
    """ Reload the modules """

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
    """ Find a matching name, and return it. Must be an exact match. """

    if not LOADED_MODULES:
        reload()

    if not isinstance(LOADED_MODULES[name], base):
        raise KeyError(name)

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
    """ Find matching modules based on Regular Expression pattern """

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
        if not re.match(pattern, module_name):
            continue

        yield module


def run(pattern: str, **kwargs):
    """ Find a module with a matching name and return the results """

    if not LOADED_MODULES:
        reload()

    if pattern not in LOADED_MODULES:
        raise ModuleNotFoundError(f"invalid module name: {pattern}")

    # Grab the module
    module = LOADED_MODULES[pattern]

    if module.PLATFORM != Platform.NO_HOST and pwncat.victim.host is None:
        raise ModuleNotFoundError(f"{module.name}: no connected victim")
    elif (
        module.PLATFORM != Platform.NO_HOST
        and pwncat.victim.host.platform not in module.PLATFORM
    ):
        raise ModuleNotFoundError(f"{module.name}: incorrect platform")

    return module.run(**kwargs)
