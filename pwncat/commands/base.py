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
    """ Only allow the user to store a value in the destination once. This prevents
    users from selection multiple actions in the privesc parser. """

    def __call__(self, parser, namespace, values, option_string=None):
        if hasattr(self, "__" + self.dest + "_seen"):
            raise argparse.ArgumentError(self, "only one action may be specified")
        setattr(namespace, "__" + self.dest + "_seen", True)
        setattr(namespace, self.dest, self.const)


def StoreForAction(action: List[str]) -> Callable:
    """ Generates a custom argparse Action subclass which verifies that the current
    selected "action" option is one of the provided actions in this function. If
    not, an error is raised. """

    class StoreFor(argparse.Action):
        """ Store the value if the currently selected action matches the list of
        actions passed to this function. """

        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, "action", None) not in action:
                raise argparse.ArgumentError(
                    self, f"{option_string}: only valid for {action}",
                )

            setattr(namespace, self.dest, values)

    return StoreFor


def RemoteFileType(file_exist=True, directory_exist=False):
    def _type(command: "CommandDefinition", name: str):
        """ Ensures that the remote file named exists. This should only be used for 
        arguments which represent files on the remote system which should be viewable
        by the running user (e.g. not helpful for privesc methods). """

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
    ARGS = {}
    """ A dictionary of parameter definitions created with the ``parameter`` function.
    If this is None, your command will receive the raw argument string and no processing
    will be done except removing the leading command name.
    """
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

    def __init__(self):
        """ Initialize a new command instance. Parse the local arguments array
        into an argparse object. """

        # Create the parser object
        if self.ARGS is not None:
            self.parser = argparse.ArgumentParser(
                prog=self.PROG, description=self.__doc__
            )
            self.build_parser(self.parser, self.ARGS)
        else:
            self.parser = None

    def run(self, args):
        """
        This is the "main" for your new command. This should perform the action
        represented by your command.
        
        :param args: the argparse Namespace containing your parsed arguments
        """
        raise NotImplementedError

    def build_parser(self, parser: argparse.ArgumentParser, args: Dict[str, Any]):
        """
        Parse the ARGS and DEFAULTS dictionaries to build an argparse ArgumentParser
        for this command. You should not need to overload this.
        
        :param parser: the parser object to add arguments to
        :param args: the ARGS dictionary
        """

        for arg, descr in args.items():
            names = arg.split(",")

            # Patch choice to work with a callable
            if "choices" in descr[3] and callable(descr[3]["choices"]):
                method = descr[3]["choices"]

                class wrapper:
                    def __init__(wself, method):
                        wself.method = method

                    def __iter__(wself):
                        yield from wself.method(self)

                descr[3]["choices"] = wrapper(method)

            # Patch "type" so we can see "self"
            if (
                "type" in descr[3]
                and isinstance(descr[3]["type"], tuple)
                and descr[3]["type"][0] == "method"
            ):
                descr[3]["type"] = partial(descr[3]["type"][1], self)

            parser.add_argument(*names, *descr[2], **descr[3])

        parser.set_defaults(**self.DEFAULTS)
