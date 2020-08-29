#!/usr/bin/env python3
from typing import Any, Callable
from dataclasses import dataclass
import pkgutil
import inspect
import re

from rich.progress import Progress

from pwncat.util import console
import pwncat

LOADED_MODULES = {}


class NoValue:
    """ Differentiates "None" from having no default value """


class ModuleNotFound(Exception):
    """ The specified module was not found """


class ArgumentFormatError(Exception):
    """ Format of one of the arguments was incorrect """


class MissingArgument(Exception):
    """ A required argument is missing """


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
        raise NotImplementedError

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

    def decorator(self, **kwargs):
        for key in kwargs:
            if key in self.ARGUMENTS:
                try:
                    kwargs[key] = self.ARGUMENTS[key].type(kwargs[key])
                except ValueError:
                    raise ArgumentFormatError(key)
        for key in self.ARGUMENTS:
            if key not in kwargs and key in pwncat.victim.config:
                kwargs[key] = pwncat.victim.config[key]
            elif key not in kwargs and self.ARGUMENTS[key].default is not NoValue:
                kwargs[key] = self.ARGUMENTS[key].default
            elif key not in kwargs and self.ARGUMENTS[key].default is NoValue:
                raise MissingArgument(key)
        # Return the result
        return real_run(self, **kwargs)

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

    def __init__(self):
        return

    def run(self, **kwargs):
        """ Execute this module """
        raise NotImplementedError


def reload():
    """ Reload the modules """

    for loader, module_name, is_pkg in pkgutil.walk_packages(
        __path__, prefix=__name__ + "."
    ):
        module = loader.find_module(module_name).load_module(module_name)

        if getattr(module, "Module", None) is None:
            continue

        module_name = module_name.split(__name__ + ".")[1]

        LOADED_MODULES[module_name] = module.Module()

        setattr(LOADED_MODULES[module_name], "name", module_name)


def find(name: str):
    """ Find a matching name, and return it. Must be an exact match. """

    if not LOADED_MODULES:
        reload()

    return LOADED_MODULES[name]


def match(pattern: str):
    """ Find matching modules based on Regular Expression pattern """

    if not LOADED_MODULES:
        reload()

    for module_name, module in LOADED_MODULES.items():
        if re.match(pattern, module_name):
            yield module


def run(pattern: str, **kwargs):
    """ Find a module with a matching name and return the results """

    if not LOADED_MODULES:
        reload()

    if pattern not in LOADED_MODULES:
        raise ModuleNotFoundError(f"invalid module name: {pattern}")

    # Grab the module
    module = LOADED_MODULES[pattern]

    with Progress(
        "collecting results",
        "•",
        pattern,
        "•",
        "[cyan]{task.fields[status]}",
        transient=True,
        console=console,
    ) as progress:
        task = progress.add_task("", status="...")

        result_object = module.run(**kwargs)

        if inspect.isgenerator(result_object):
            results = []
            for item in result_object:
                progress.update(task, status=str(item))
                if not isinstance(item, Status):
                    results.append(item)
        else:
            results = result_object

    return results
