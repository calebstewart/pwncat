#!/usr/bin/env python3
from typing import List, Dict, Any, Callable
from shlex import quote
import binascii
import base64
import shlex
import json
import os


class SudoNotPossible(Exception):
    """ Running the given binary to get a sudo shell is not possible """


class Binary:

    _binaries: List[Dict[str, Any]] = []

    def __init__(self, path: str, data: Dict[str, Any]):
        """ build a new binary from a dictionary of data. The data is taken from
        the GTFOBins JSON database """
        self.data = data
        self.path = path

    def shell(
        self,
        shell_path: str,
        sudo_prefix: str = None,
        command: str = None,
        suid: bool = False,
    ) -> str:
        """ Build a a payload which will execute the binary and result in a
        shell. `path` should be the path to the shell you would like to run. In
        the case of GTFOBins that _are_ shells, this will likely be ignored, but
        you should always provide it.
        """

        if "shell" not in self.data:
            return None

        if isinstance(self.data["shell"], str):
            script = self.data["shell"].format(shell=shell_path, command="{command}")
            args = []
            suid_args = []
            exit = "exit"
            input = ""
        else:
            script = (
                self.data["shell"]
                .get("script", "{command}")
                .format(shell=shell_path, command="{command}")
            )
            suid_args = self.data["shell"].get("suid", [])
            args = [
                n.format(shell=shell_path) for n in self.data["shell"].get("need", [])
            ]
            exit = self.data["shell"].get("exit", "exit")
            input = self.data["shell"].get("input", "")

        if suid:
            suid_args.extend(args)
            args = suid_args

        if script == "":
            script = "{command}"

        if command is None:
            command = shlex.join([self.path] + args)
            if sudo_prefix is not None:
                command = sudo_prefix + " " + command

        return (
            script.format(command=command),
            input.format(shell=shlex.quote(shell_path)),
            exit,
        )

    @property
    def has_shell(self) -> bool:
        """ Check if this binary has a shell method """
        return "shell" in self.data

    def can_sudo(self, command: str, shell_path: str) -> List[str]:
        """ Checks if this command can be leveraged for a shell with sudo. The
        GTFObin specification must include information on the sudo context. It
        will check either:
            
            * There are no parameters in the sudo specification, it succeeds.
            * There are parameters, but ends in a start, we succeed (doesn't
              guarantee successful shell, but is more likely)
            * Parameters match exactly
        """

        if not self.has_shell:
            # We need to be able to run a shell
            raise SudoNotPossible

        # Split the sudo command specification
        args = shlex.split(command.rstrip("*"))

        # There was a " *" which is not a wildcard
        if shlex.split(command)[-1] == "*":
            has_wildcard = False
            args.append("*")
        elif command[-1] == "*":
            has_wildcard = True

        if isinstance(self.data["shell"], str):
            need = [n.format(shell=shell_path) for n in shlex.split(self.data["shell"])]
            restricted = []
        else:
            # Needed and restricted parameters
            need = [
                n.format(shell=shell_path) for n in self.data["shell"].get("need", [])
            ]
            restricted = self.data["shell"].get("restricted", [])

        # The sudo command is just "/path/to/binary", we are allowed to add any
        # parameters we want.
        if len(args) == 1 and command[-1] != " ":
            return need

        # Check for disallowed arguments
        for arg in args:
            if arg in restricted:
                raise SudoNotPossible

        # Check if we already have the parameters we need
        needed = {k: False for k in need}
        for arg in args:
            if arg in needed:
                needed[arg] = True

        # Check if we have any missing needed parameters, and no wildcard
        # was given
        if any([not v for _, v in needed.items()]) and not has_wildcard:
            raise SudoNotPossible

        # Either we have all the arguments we need, or we have a wildcard
        return [k for k, v in needed.items() if not v]

    def sudo_shell(self, user: str, spec: str, shell_path: str) -> str:
        """ Generate a payload to get a shell with sudo for this binary. This
        can be complicated, since the sudo specification may include wildcards 
        or other parameters we don't want. We leverage the information in the 
        GTFObins JSON data to determine if it is possible (see `can_sudo`) and
        then build a payload that should run under the given sudo specification.
        """

        # If we can't this will raise an exception up to the caller
        needed_args = self.can_sudo(spec, shell_path)

        prefix = f"sudo -u {user}"

        if spec.endswith("*") and not spec.endswith(" *"):
            spec = spec.rstrip("*")

        # There's more arguments we need, and we're allowed to pass them
        if needed_args:
            command = spec + " " + " ".join(needed_args)
        else:
            command = spec

        command = prefix + " " + command

        return self.shell(shell_path, command=command)

    def sudo(self, sudo_prefix: str, command: str, shell_path: str) -> str:
        """ Build a a payload which will execute the binary and result in a
        shell. `path` should be the path to the shell you would like to run. In
        the case of GTFOBins that _are_ shells, this will likely be ignored, but
        you should always provide it.
        """

        if "sudo" not in self.data:
            return None

        if isinstance(self.data["sudo"], str):
            enter = self.data["sudo"]
            exit = "exit"
            input = ""
        else:
            enter = self.data["sudo"]["enter"]
            exit = self.data["sudo"].get("exit", "exit")
            input = self.data["shell"].get("input", "input")

        return (
            enter.format(
                path=quote(self.path),
                shell=quote(shell_path),
                command=quote(command),
                sudo_prefix=sudo_prefix,
            ),
            input.format(shell=quote(shell_path)),
            exit,
        )

    def read_file(self, file_path: str) -> str:
        """ Build a payload which will leak the contents of the specified file.
        """

        if "read_file" not in self.data:
            return None

        return self.data["read_file"].format(
            path=quote(self.path), lfile=quote(file_path)
        )

    @property
    def has_read_file(self):
        """ Check if this binary has a read_file capability """
        return "read_file" in self.data

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

    @property
    def has_write_file(self):
        """ Check if this binary has a write_file capability """
        return "write_file" in self.data

    def command(self, command: str) -> str:
        """ Build a payload to execute the specified command """

        if "command" not in self.data:
            return None

        return self.data["command"].format(
            path=quote(self.path), command=quote(command)
        )

    @property
    def has_command(self):
        """ Check if this binary has a command capability """
        return "command" in self.data

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

    @classmethod
    def find_sudo(cls, spec: str, get_binary_path: Callable[[str], str]) -> "Binary":
        """ Locate a GTFObin binary for the given sudo spec. This will separate 
        out the path of the binary from spec, and use `find` to locate a Binary
        object. If that binary cannot be used with this spec or no binary exists,
        SudoNotPossible is raised. shell_path is used as the default for specs
        which specify "ALL". """

        if spec == "ALL":
            # If the spec specifies any command, we check each known gtfobins
            # binary for one usable w/ this sudo spec. We use recursion here,
            # but never more than a depth of one, so it should be safe.
            for data in cls._binaries:
                # Resolve the binary path from the name
                path = get_binary_path(data["name"])

                # This binary doens't exist on the system
                if path is None:
                    continue

                try:
                    # Recurse using the path as the new spec (won't recurse
                    # again since spec is now a full path)
                    return cls.find_sudo(path, get_binary_path)
                except SudoNotPossible:
                    pass
            raise SudoNotPossible("no available gtfobins for ALL")

        path = shlex.split(spec)[0]
        binary = cls.find(path)

        if binary is None:
            raise SudoNotPossible(f"no available gtfobins for {spec}")

        # This will throw an exception if we can't sudo with this binary
        _ = binary.can_sudo(spec, "")

        return spec, binary
