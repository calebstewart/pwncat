#!/usr/bin/env python3
from typing import List, Dict, Any
from shlex import quote
import binascii
import base64
import json
import os


class Binary:

    _binaries: List[Dict[str, Any]] = []

    def __init__(self, path: str, data: Dict[str, Any]):
        """ build a new binary from a dictionary of data. The data is taken from
        the GTFOBins JSON database """
        self.data = data
        self.path = path

    def shell(self, shell_path: str) -> str:
        """ Build a a payload which will execute the binary and result in a
        shell. `path` should be the path to the shell you would like to run. In
        the case of GTFOBins that _are_ shells, this will likely be ignored, but
        you should always provide it.
        """

        if "shell" not in self.data:
            return None

        if isinstance(self.data["shell"], str):
            enter = self.data["shell"]
            exit = "exit"
        else:
            enter = self.data["shell"]["enter"]
            exit = self.data["shell"].get("exit", "exit")

        return enter.format(path=quote(self.path), shell=quote(shell_path)), exit

    def read_file(self, file_path: str) -> str:
        """ Build a payload which will leak the contents of the specified file.
        """

        if "read_file" not in self.data:
            return None

        return self.data["read_file"].format(
            path=quote(self.path), lfile=quote(file_path)
        )

    def write_file(self, file_path: str, data: bytes) -> str:
        """ Build a payload to write the specified data into the file """

        if "write_file" not in self.data:
            return None

        if isinstance(data, str):
            data = data.encode("utf-8")

        if self.data["write_file"]["type"] == "base64":
            data = base64.b64encode(data)
        elif self.data["write_file"]["type"] == "hex":
            data = binascii.hexlify(data)
        elif self.data["write_file"]["type"] != "raw":
            raise RuntimeError(
                "{self.data['name']}: unknown write_file type: {self.data['write_file']['type']}"
            )

        return self.data["write_file"]["payload"].format(
            path=quote(self.path),
            lfile=quote(file_path),
            data=quote(data.decode("utf-8")),
        )

    def command(self, command: str) -> str:
        """ Build a payload to execute the specified command """

        if "command" not in self.data:
            return None

        return self.data["command"].format(
            path=quote(self.path), command=quote(command)
        )

    @classmethod
    def load(cls, gtfo_path: str):
        with open(gtfo_path) as filp:
            cls._binaries = json.load(filp)

    @classmethod
    def find(cls, path: str, name: str = None) -> "Binary":
        """ Locate the given gtfobin and return the Binary object. If name is
        not given, it is assumed to be the basename of the path. """

        if name is None:
            name = os.path.basename(path)

        for binary in cls._binaries:
            if binary["name"] == name:
                return Binary(path, binary)

        return None
