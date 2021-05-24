#!/usr/bin/env python3
import os
import re
import copy
import ipaddress
from typing import Any, Dict, List, Union

from prompt_toolkit.keys import ALL_KEYS, Keys
from prompt_toolkit.input.ansi_escape_sequences import (ANSI_SEQUENCES,
                                                        REVERSE_ANSI_SEQUENCES)

from pwncat.modules import BaseModule


def key_type(value: str) -> bytes:
    """Converts a key name to a ansi keycode. The value can either be a single
    printable character or a named key from prompt_toolkit Keys"""
    if len(value) == 1:
        return value.encode("utf-8")
    if value not in ALL_KEYS:
        raise ValueError(f"invalid key: {value}")
    key = [key for key in Keys if key.value == value][0]
    return REVERSE_ANSI_SEQUENCES[key].encode("utf-8")


class KeyType:
    def __init__(self, name: str):
        if len(name) == 1:
            self.value = name.encode("utf-8")
        else:
            if name not in ALL_KEYS:
                raise ValueError(f"{name}: invalid key")
            key = [key for key in Keys if key.value == name][0]
            self.value = REVERSE_ANSI_SEQUENCES[key].encode("utf-8")
        self.name = name

    def __repr__(self):
        return f"Key(name={repr(self.name)})"

    def __bytes__(self):
        return self.value


def local_file_type(value: str) -> str:
    """ Ensure the local file exists """
    if not os.path.isfile(value):
        raise ValueError(f"{value}: no such file or directory")
    return value


def local_dir_type(value: str) -> str:
    """ Ensure the path specifies a local directory """

    if not os.path.isdir(value):
        raise ValueError(f"{value}: no such file or directory")
    return value


def bool_type(value: str) -> bool:

    if isinstance(value, bool):
        return value

    value = value.lower()
    if value == "1" or value == "true" or value == "on":
        return True
    elif value == "0" or value == "false" or value == "off":
        return False

    raise ValueError(f"{value}: expected boolean value")


class Config:
    def __init__(self):

        # Basic key-value store w/ typing
        self.values: Dict[str, Dict[str, Any]] = {
            "lhost": {
                "value": ipaddress.ip_address("127.0.0.1"),
                "type": ipaddress.ip_address,
            },
            "prefix": {"value": KeyType("c-k"), "type": KeyType},
            "privkey": {"value": "data/pwncat", "type": local_file_type},
            "backdoor_user": {"value": "pwncat", "type": str},
            "backdoor_pass": {"value": "pwncat", "type": str},
            "on_load": {"value": "", "type": str},
            "db": {"value": "memory://", "type": str},
            "cross": {"value": None, "type": str},
            "psmodules": {"value": ".", "type": local_dir_type},
            "verbose": {"value": False, "type": bool_type},
            "windows_c2_dir": {
                "value": "~/.local/share/pwncat",
                "type": local_dir_type,
            },
        }

        # Locals are set per-used-module
        self.locals: Dict[str, Any] = {}
        self.module: BaseModule = None

        # Map ascii escape sequences or printable bytes to lists of commands to
        # run.
        self.bindings: Dict[KeyType, str] = {
            KeyType("c-d"): "pass",
            KeyType("s"): "sync",
            KeyType("c"): "set state command",
        }

    def copy(self) -> "Config":
        """Copy this configuration object exactly. This is mainly used
        to allow for the possibility of running modules in the background
        without being affected by future configuration changes."""

        new = Config()

        new.values = copy.copy(self.values)
        new.locals = copy.copy(self.locals)
        new.module = self.module
        new.bindings = copy.copy(self.bindings)

        return new

    def binding(self, name_or_value: Union[str, bytes]) -> str:
        """ Get a key binding by it's key name or key value. """

        if isinstance(name_or_value, bytes):
            binding = [
                b for key, b in self.bindings.items() if key.value == name_or_value
            ]
            if not binding:
                raise KeyError("no such key binding")
            return binding[0]

        key = KeyType(name_or_value)
        return self.bindings[key]

    def set(self, name: str, value: Any, glob: bool = False):
        """ Set a config value """

        if (
            (glob and name not in self.values)
            or (name not in self.values and self.module is None)
            or (
                self.module is not None
                and name not in self.values
                and name not in self.module.ARGUMENTS
            )
        ):
            raise KeyError(f"{name}: no such configuration value")

        if glob or self.module is None or name not in self.module.ARGUMENTS:
            self.values[name]["value"] = self.values[name]["type"](value)
        else:
            self.locals[name] = self.module.ARGUMENTS[name].type(value)

    def get(self, name: str, default=None):
        """ get a value """

        try:
            return self[name]
        except KeyError:
            return default

    def use(self, module: BaseModule):
        """Use the specified module. This clears the current
        locals configuration."""

        self.locals = {}
        self.module = module

    def back(self):
        """ Remove the currently used module and clear locals """

        self.locals = {}
        self.module = None

    def __getitem__(self, name: str) -> Any:
        """ Get a configuration item """

        if name in self.locals:
            return self.locals[name]

        return self.values[name]["value"]

    def __setitem__(self, name: str, value: Any):
        """ Set a configuration item """
        return self.set(name, value, glob=False)

    def __iter__(self):
        # NOTE - this is bad. We should deconflict
        yield from self.values
        yield from self.locals
