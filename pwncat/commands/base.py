#!/usr/bin/env python3
from typing import Dict, Any
from pygments.token import *
from enum import Enum, auto
from functools import partial
import argparse


class Complete(Enum):
    # Complete from the choices array in kwargs
    CHOICES = auto()
    # Complete from a local file
    LOCAL_FILE = auto()
    # Complete from a remote file
    REMOTE_FILE = auto()
    # This argument has no parameter
    NONE = auto()


def parameter(complete, token=Name.Label, *args, **kwargs):
    """ Build a parameter tuple from argparse arguments """
    return (complete, token, args, kwargs)


class CommandDefinition:
    """ Default help/description goes here """

    PROG = "unimplemented"
    ARGS = {}
    DEFAULTS = {}

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

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        """ Initialize a new command instance. Parse the local arguments array
        into an argparse object. """

        self.pty = pty

        # Create the parser object
        self.parser = argparse.ArgumentParser(prog=self.PROG, description=self.__doc__)

        self.build_parser(self.parser, self.ARGS)

    def run(self, args):
        """ Perform whatever your command is. `args` has already been parsed with
        your argparse definitions. """
        raise NotImplementedError

    def build_parser(self, parser: argparse.ArgumentParser, args: Dict[str, Any]):
        """ Fill the given parser with arguments based on the dict """

        for arg, descr in args.items():
            names = arg.split(",")
            if "choices" in descr[3] and callable(descr[3]["choices"]):
                print("we're doing it", descr[3]["choices"])
                method = descr[3]["choices"]

                class wrapper:
                    def __iter__(wself):
                        yield from method(self)

                descr[3]["choices"] = wrapper()
            parser.add_argument(*names, *descr[2], **descr[3])

        parser.set_defaults(**self.DEFAULTS)
