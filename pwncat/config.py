#!/usr/bin/env python3
from prompt_toolkit.input.ansi_escape_sequences import REVERSE_ANSI_SEQUENCES
from prompt_toolkit.keys import ALL_KEYS, Keys
from typing import Any, Dict, List
import commentjson as json
import ipaddress
import re
import os


def key_type(value: str) -> bytes:
    """ Converts a key name to a ansi keycode. The value can either be a single 
    printable character or a named key from prompt_toolkit Keys """
    if len(value) == 1:
        return value.encode("utf-8")
    if value not in ALL_KEYS:
        raise ValueError(f"invalid key: {value}")
    key = [key for key in Keys if key.value == value][0]
    return REVERSE_ANSI_SEQUENCES[key].encode("utf-8")


class KeyType:
    def __init__(self, name: str):
        if len(name) == 1:
            self.name = name
            self.value = name.encode("utf-8")
        else:
            if name not in ALL_KEYS:
                raise ValueError(f"{name}: invalid key")
            key = [key for key in Keys if key.value == name][0]
            self.name = name
            self.value = REVERSE_ANSI_SEQUENCES[key].encode("utf-8")

    def __repr__(self):
        return f"Key(name={repr(self.name)})"

    def __bytes__(self):
        return self.value


def local_file_type(value: str) -> str:
    """ Ensure the local file exists """
    if not os.path.isfile(value):
        raise ValueError(f"{value}: no such file or directory")
    return value


class Config:
    def __init__(self, pty: "pwncat.pty.PtyHandler"):

        # Basic key-value store w/ typing
        self.values: Dict[str, Dict[str, Any]] = {
            "lhost": {"value": None, "type": ipaddress.ip_address},
            "prefix": {"value": "C-k", "type": KeyType},
            "privkey": {"value": "data/pwncat", "type": local_file_type},
            "backdoor_user": {"value": "pwncat", "type": str},
            "backdoor_pass": {"value": "pwncat", "type": str},
            "on_load": {"value": "", "type": str},
        }

        # Map ascii escape sequences or printable bytes to lists of commands to
        # run.
        self.bindings: Dict[bytes, str] = {}

    def __getitem__(self, name: str) -> Any:
        """ Get a configuration item """
        return self.values[name]["value"]

    def __setitem__(self, name: str, value: Any):
        """ Set a configuration item """
        item = self.values[name]
        item["value"] = item["type"](value)

    def __iter__(self):
        yield from self.values
