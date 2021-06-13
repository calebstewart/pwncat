"""
pwncat modules are the core extensible feature of pwncat. They provide a way for users to execute
complex scripted target interaction efficiently from the local prompt. The most extensive feature
is the enumeration modules allowing the user to quickly enumerate commonly useful information from
the target, and save the data in a database for future access.

There are standard modules implemented for enumerating arbitrary data, managing installed implants,
and generating formatted reports on your targets. Modules are loaded from within the pwncat package
by default, but can be loaded from other locations with the ``load`` command or the
:func:`pwncat.manager.Manager.load_modules` method. When loading custom modules, a path to a Python
package is given and any module within the package which defines a ``Module`` class that inherits
from :class:`pwncat.modules.BaseModule` will be imported and added to the module list.

For an up-to-date list of standard modules and their usage, please consult the internal pwncat
help/info documentation.

Example Module
--------------

.. code-block:: python
    :caption: Example Base Module

    class Module(BaseModule):
        \"\"\" Module Documentation \"\"\"

        PLATFORM = [Linux]
        ARGUMENTS = { "arg": Argument(str, help="help string") }

        def run(self, session: "pwncat.manager.Session", arg: str):
            yield Status("A status message!")
            session.log(f"ran {self.name}")

"""
import typing
import inspect
import functools
from typing import Any, Dict, Callable, Optional
from dataclasses import dataclass

import pwncat

LOADED_MODULES = {}


class NoValue:
    """ Indicates that the module argument has no default value and is required. """


class ModuleFailed(Exception):
    """Base class for module failure"""


class ModuleNotFound(ModuleFailed):
    """The specified module was not found"""


class IncorrectPlatformError(ModuleFailed):
    """The requested module didn't match the current platform"""


class ArgumentFormatError(ModuleFailed):
    """Format of one of the arguments was incorrect"""


class MissingArgument(ModuleFailed):
    """A required argument is missing"""


class InvalidArgument(ModuleFailed):
    """This argument does not exist and ALLOW_KWARGS was false"""


@dataclass
class Argument:
    """Describes an individual module argument. Arguments to modules are
    always required. If an argument has the default :class:`NoValue` then
    the module will fail if no value is provided by the user."""

    type: Callable[[str], Any] = str
    """ A callable which converts a string to the required type
    This function should also return the passed value if it is
    already of that type. A :class:`ValueError` is raised if
    conversion is not possible. """
    default: Any = NoValue
    """ The default value for this argument. If set to :class:`NoValue`, the
    argument **must** be set by the user. """
    help: str = ""
    """ The help text displayed in the ``info`` output. """


def List(_type=str):
    """Argument list type, which accepts a list of the provided
    type. By default, this accepts a list of strings."""

    def _ListType(value):
        if isinstance(value, list):
            return [_type(item) for item in value]
        return [_type(item) for item in value.split(",")]

    _ListType.__repr__ = lambda self: f"List[{_type}]"

    return _ListType


def Bool(value: str):
    """Argument of type "bool". Accepts true/false (case-insensitive)
    as well as 1/0. The presence of an argument of type "Bool" with no
    assignment (e.g. ``run module arg``) is equivalent to ``run module arg=true``."""

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
    """This class defines the interface for module results. Modules can
    yield or return results as needed, but each results must implement
    this interface. Inheriting from this class is enough to provide a
    suitable result, but it is recommended to override the :func:`title`
    method in order to provide a formatted title for your result. The
    :func:`category` method helps when organizing output with the ``run``
    command."""

    hidden: bool = False
    """ Hide results from automatic display with the ``run`` command """

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
    """Decorate a run function to evaluate types. This is an internal method.
    Every module's ``run`` method is decorated with this in order to first check
    arguments against the module definition and type-check/convert to the appropriate
    types. It is also responsible for creating the progress bar, collecting results
    and committing database changes."""

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
    """This is a metaclass which is used to ensure the ``run`` method is decorated
    properly for all modules."""

    def __new__(cls, name, bases, local):
        if "run" in local:
            local["run"] = run_decorator(local["run"])
        return super().__new__(cls, name, bases, local)


class BaseModule(metaclass=BaseModuleMeta):
    """Generic module class. This class allows to easily create
    new modules. Any new module must inherit from this class. The
    run method is guaranteed to receive as key-word arguments any
    arguments specified in the ``ARGUMENTS`` dictionary.

    Results from the module are normally returned via the ``yield``
    instruction. This allows pwncat to collect results and provide
    status output. However, you can also return a single item with
    the ``return`` statement. The :func:`pwncat.manager.Session.run`
    method will by default normally return an array. If you module
    only has a single result, you can set the ``COLLAPSE_RESULT``
    property to ``True`` to tell pwncat to collapse a single-item
    array into a regular value.

    If your module should take arbitrary, unnamed keyword arguments,
    you can use set the ``ALLOW_KWARGS`` property, which allows the
    user to pass arbitrary key-value pairs to your module. These
    values will normally be strings, but it is the responsibility of
    the module to conduct type-checking.

    If the module is not platform-dependent, you can set the ``PLATFORM``
    property to ``None``.
    """

    ARGUMENTS: Dict[str, Argument] = {
        # "name": Argument(int, default="value"),
        # "name2": Argument(List(int), default=[1, 2, 3]),
    }
    """ Arguments which can be provided to the ``run`` method.
    This maps argument names to ``Argument`` instances describing
    the type, default value, and requirements for an individual
    argument.
    """
    ALLOW_KWARGS: bool = False
    """ Allow other kwargs parameters outside of what is specified by
    the arguments dictionary. This allows arbitrary arguments which
    are not type-checked to be passed. You should use `**kwargs` in
    your run method if this is set to True. """
    COLLAPSE_RESULT: bool = False
    """ If you want to use `yield Status(...)` to update the progress bar
    but only return one scalar value, setting this to true will collapse
    an array with only a single object to it's scalar value. """
    PLATFORM: typing.List[typing.Type["pwncat.platform.Platform"]] = []
    """ The platform this module is compatibile with (can be multiple) """

    def __init__(self):
        self.progress = None
        # Filled in by reload
        self.name = None

    def run(
        self,
        session: "pwncat.manager.Session",
        progress: Optional[bool] = None,
        **kwargs,
    ):
        """The run method is called via keyword-arguments with all the
        parameters specified in the ``ARGUMENTS`` dictionary. If ``ALLOW_KWARGS``
        was True, then other keyword arguments may also be passed. Any
        types specified in ``ARGUMENTS`` will already have been checked.

        If there are any errors while processing a module, the module should
        raise ``ModuleError`` or a subclass in order to enable ``pwncat`` to
        automatically and gracefully handle a failed module execution.

        If ``progress`` is None, the visibility of progress information
        will be inherited from the parent module. If this module was run
        directly by the framework, the default is to display progress
        information. If ``progress`` is False, no progress information
        will be displayed and any subsequent modules which set progress
        to None will not display progress information.

        :param session: the active session
        :type session: pwncat.manager.Session
        :param progress: whether to show progress information for this and subsequent modules
        :type progress: Optional[bool]
        """

        raise NotImplementedError
