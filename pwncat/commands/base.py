#!/usr/bin/env python3
from typing import Dict, Any, List, Callable
from pygments.token import *
from enum import Enum, auto
from functools import partial
import argparse
import shlex
import os

import pwncat


class Complete(Enum):
    """
    Command argument completion options

    """

    # Complete from the choices array in kwargs
    CHOICES = auto()
    """ Complete argument from the list of choices specified in ``parameter`` """
    # Complete from a local file
    LOCAL_FILE = auto()
    """ Complete argument as a local file path """
    # Complete from a remote file
    REMOTE_FILE = auto()
    """ Complete argument as a remote file path """
    # This argument has no parameter
    NONE = auto()
    """ Do not provide argument completions """


class StoreConstOnce(argparse.Action):
    """Only allow the user to store a value in the destination once. This prevents
    users from selection multiple actions in the privesc parser."""

    def __call__(self, parser, namespace, values, option_string=None):
        if hasattr(self, "__" + self.dest + "_seen"):
            raise argparse.ArgumentError(self, "only one action may be specified")
        setattr(namespace, "__" + self.dest + "_seen", True)
        setattr(namespace, self.dest, self.const)


def StoreForAction(action: List[str]) -> Callable:
    """Generates a custom argparse Action subclass which verifies that the current
    selected "action" option is one of the provided actions in this function. If
    not, an error is raised."""

    class StoreFor(argparse.Action):
        """Store the value if the currently selected action matches the list of
        actions passed to this function."""

        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, "action", None) not in action:
                raise argparse.ArgumentError(
                    self,
                    f"{option_string}: only valid for {action}",
                )

            setattr(namespace, self.dest, values)

    return StoreFor


def StoreConstForAction(action: List[str]) -> Callable:
    """Generates a custom argparse Action subclass which verifies that the current
    selected "action" option is one of the provided actions in this function. If
    not, an error is raised. This stores the constant `const` to the `dest` argument.
    This is comparable to `store_const`, but checks that you have selected one of
    the specified actions."""

    class StoreFor(argparse.Action):
        """Store the value if the currently selected action matches the list of
        actions passed to this function."""

        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, "action", None) not in action:
                raise argparse.ArgumentError(
                    self,
                    f"{option_string}: only valid for {action}",
                )

            setattr(namespace, self.dest, self.const)

    return StoreFor


def RemoteFileType(file_exist=True, directory_exist=False):
    def _type(command: "CommandDefinition", name: str):
        """Ensures that the remote file named exists. This should only be used for
        arguments which represent files on the remote system which should be viewable
        by the running user (e.g. not helpful for privesc methods)."""

        # Attempt to find the "test" command
        test = pwncat.victim.which("test")
        if test is None:
            test = pwncat.victim.which("[")

        # No test command, this is a nicety, not a necessity.
        if test is None:
            return name

        # Check if the file exists
        if file_exist:
            result = pwncat.victim.run(f"{test} -f {shlex.quote(name)} && echo exists")
            if b"exists" not in result:
                raise argparse.ArgumentTypeError(f"{name}: no such file or directory")
        elif directory_exist:
            dirpath = os.path.dirname(name)
            result = pwncat.victim.run(
                f"{test} -d {shlex.quote(dirpath)} && echo exists"
            )
            if b"exists" not in result:
                raise argparse.ArgumentTypeError(
                    f"{dirpath}: no such file or directory"
                )

        # it exists
        return name

    return _type


class Parameter:
    """Generic parameter definition for commands.

    This isn't in use yet, but I'd like to transition to this as it's:

        1. Easier to read/follow than a tuple
        2. Allows for group and mutex group definitions

    However, it requires changing every single command definition and also
    changing all the processing of those command definitions in __init__ and base... :(

    :param complete: the completion type
    :type complete: Complete
    :param token: the Pygments token to highlight this argument with
    :type token: Pygments Token
    :param group: true for a group definition, a string naming the group to be a part of, or none
    :param mutex: for group definitions, indicates whether this is a mutually exclusive group
    :param args: positional arguments for ``add_argument`` or ``add_argument_group``
    :param kwargs: keyword arguments for ``add_argument`` or ``add_argument_group``
    """

    def __init__(
        self,
        complete: Complete,
        token=Name.Label,
        group: str = None,
        *args,
        **kwargs,
    ):
        self.complete = complete
        self.token = token
        self.group = group
        self.args = args
        self.kwargs = kwargs


class Group:
    """
    This just wraps the parameters to the add_argument_group and add_mutually_exclusive_group
    """

    def __init__(self, mutex: bool = False, **kwargs):
        self.mutex = mutex
        self.kwargs = kwargs


def parameter(complete, token=Name.Label, *args, **kwargs):
    """
    Generate a parameter definition from completer options, token definition,
    and argparse add_argument options.

    :param complete: the completion type
    :type complete: Complete
    :param token: the Pygments token to highlight this argument with
    :type token: Pygments Token
    :param args: positional arguments for ``add_argument``
    :param kwargs: keyword arguments for ``add_argument``
    :return: Parameter definition
    """
    return (complete, token, args, kwargs)


class CommandDefinition:
    """
    Generic structure for a local command. The docstring for your command class becomes
    the long-form help for your command.
    """

    PROG = "unimplemented"
    """ The name of your new command """
    ARGS: Dict[str, Parameter] = {}
    """ A dictionary of parameter definitions created with the ``Parameter`` class.
    If this is None, your command will receive the raw argument string and no processing
    will be done except removing the leading command name.
    """
    GROUPS: Dict[str, Group] = {}
    """ A dictionary mapping group definitions to group names. The parameters to Group
    are passed directly to either add_argument_group or add_mutually_exclusive_group
    with the exception of the mutex arg, which determines the group type. """
    DEFAULTS = {}
    """ A dictionary of default values (passed directly to ``ArgumentParser.set_defaults``) """
    LOCAL = False
    """ Whether this command is purely local or requires an connected remote host """

    # An example definition of arguments
    # PROG = "command"
    # ARGS = {
    #     "--all,-a": parameter(
    #         Complete.NONE, action="store_true", help="A switch/option"
    #     ),
    #     "--file,-f": parameter(Complete.LOCAL_FILE, help="A local file"),
    #     "--rfile": parameter(Complete.REMOTE_FILE, help="A remote file"),
    #     "positional": parameter(
    #         Complete.CHOICES, choices=["a", "b", "c"], help="Choose one!"
    #     ),
    # }

    def __init__(self, manager: "pwncat.manager.Manager"):
        """Initialize a new command instance. Parse the local arguments array
        into an argparse object."""

        self.manager = manager

        # Create the parser object
        if self.ARGS is not None:
            self.parser = argparse.ArgumentParser(
                prog=self.PROG,
                description=self.__doc__,
                formatter_class=argparse.RawDescriptionHelpFormatter,
            )
            self.build_parser(self.parser, self.ARGS, self.GROUPS)
        else:
            self.parser = None

    def run(self, manager: "pwncat.manager.Manager", args):
        """
        This is the "main" for your new command. This should perform the action
        represented by your command.

        :param manager: the manager to operate on
        :type manager: pwncat.manager.Manager
        :param args: the argparse Namespace containing your parsed arguments
        """
        raise NotImplementedError

    def build_parser(
        self,
        parser: argparse.ArgumentParser,
        args: Dict[str, Parameter],
        group_defs: Dict[str, Group],
    ):
        """
        Parse the ARGS and DEFAULTS dictionaries to build an argparse ArgumentParser
        for this command. You should not need to overload this.

        :param parser: the parser object to add arguments to
        :param args: the ARGS dictionary
        """

        groups = {}
        for name, definition in group_defs.items():
            if definition.mutex:
                groups[name] = parser.add_mutually_exclusive_group(**definition.kwargs)
            else:
                groups[name] = parser.add_argument_group(**definition.kwargs)

        for arg, param in args.items():
            names = arg.split(",")

            if param.group is not None and param.group not in groups:
                raise ValueError(f"{param.group}: no such group")

            if param.group is not None:
                group = groups[param.group]
            else:
                group = parser

            # Patch choice to work with a callable
            if "choices" in param.kwargs and callable(param.kwargs["choices"]):
                method = param.kwargs["choices"]

                class wrapper:
                    def __init__(wself, method):
                        wself.method = method

                    def __iter__(wself):
                        yield from wself.method(self)

                param.kwargs["choices"] = wrapper(method)

            # Patch "type" so we can see "self"
            if (
                "type" in param.kwargs
                and isinstance(param.kwargs["type"], tuple)
                and param.kwargs["type"][0] == "method"
            ):
                param.kwargs["type"] = partial(param.kwargs["type"][1], self)

            group.add_argument(*names, *param.args, **param.kwargs)

        parser.set_defaults(**self.DEFAULTS)
