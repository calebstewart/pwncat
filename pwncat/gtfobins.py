#!/usr/bin/env python3
from typing import List, Dict, Any, Callable
from shlex import quote
import binascii
import base64
import shlex
import json
import os

from pwncat.privesc import Capability
from pwncat import util


class MissingBinary(Exception):
    """ The GTFObin method you attempted depends on a missing binary """


class SudoNotPossible(Exception):
    """ Running the given binary to get a sudo shell is not possible """


class FileReadNotPossible(Exception):
    """ Running the given binary to get a sudo shell is not possible """


class FileWriteNotPossible(Exception):
    """ Running the given binary to get a sudo shell is not possible """


class Binary:

    _binaries: List[Dict[str, Any]] = []

    def __init__(self, path: str, data: Dict[str, Any], which):
        """ build a new binary from a dictionary of data. The data is taken from
        the GTFOBins JSON database """
        self.data = data
        self.path = path
        self.which = which

        self.capabilities = 0
        if self.has_read_file:
            self.capabilities |= Capability.READ
        if self.has_shell:
            self.capabilities |= Capability.SHELL
        if self.has_write_file:
            self.capabilities |= Capability.WRITE
        if self.has_write_stream:
            self.capabilities |= Capability.WRITE_STREAM

        # We need to fix this later...?
        if self.has_shell:
            self.capabilities |= Capability.SUDO

    def resolve_binaries(self, target: str, **args):
        """ resolve any missing binaries with the self.which method """

        while True:
            try:
                target = target.format(**args)
                break
            except KeyError as exc:
                # The keyerror has the name in quotes for some reason
                key = shlex.split(str(exc))[0]

                quote = True
                if key.startswith("unquote_"):
                    key = key.split("unquote_")[1]
                    quote = False
                # Find the remote binary that matches
                value = self.which(key, quote=quote)
                # Whoops! No dependancy
                if value is None:
                    raise MissingBinary(key)
                # Next time, we have it
                args[key] = value

        return target

    def parse_entry(self, entry, sudo_prefix: str = None, suid=False, **args):
        """ Parse an entry for read_file, write_file, or shell """

        if isinstance(entry, str):
            entry = shlex.split(entry)
            payload = entry[0]
            args = entry[1:]
            input_data = ""
            stream_type = "print"
            exit_command = ""
            suid_args = []
        else:
            payload = entry.get("payload", "{command}")
            args = entry.get("args", [])
            input_data = entry.get("input", "")
            stream_type = entry.get("type", "print")
            exit_command = entry.get("exit", "")
            suid_args = entry.get("suid", [])

        command = self.path
        if sudo_prefix:
            command = sudo_prefix + " " + command

        args = [self.resolve_binaries(a, **args) for a in args]
        input_data = self.resolve_binaries(input_data, ctrl_c=util.CTRL_C, **args)
        exit_command = self.resolve_binaries(exit_command, ctrl_c=util.CTRL_C, **args)
        suid_args = self.resolve_binaries(suid_args, **args)

        if len(suid_args):
            command = command + " " + shlex.join(suid_args)
        if len(args):
            command = command + " " + shlex.join(args)

        payload = self.resolve_binaries(payload, command=command, **args)

        return payload, input_data, exit_command, stream_type

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
            script = self.data["shell"]
            args = []
            suid_args = []
            exit = "exit"
            input = ""
        else:
            script = self.data["shell"].get("script", "{command}")
            suid_args = self.data["shell"].get("suid", [])
            args = [
                self.resolve_binaries(n, shell=shell_path)
                for n in self.data["shell"].get("need", [])
            ]
            exit = self.resolve_binaries(self.data["shell"].get("exit", "exit"))
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
            self.resolve_binaries(script, command=command, shell=shell_path),
            input.format(shell=shlex.quote(shell_path)),
            exit,
        )

    @property
    def has_shell(self) -> bool:
        """ Check if this binary has a shell method """
        try:
            result = self.shell("test")
        except MissingBinary:
            return False
        return result is not None

    def can_sudo(self, command: str, shell_path: str) -> List[str]:
        """ Checks if this command can be leveraged for a shell with sudo. The
        GTFObin specification must include information on the sudo context. It
        will check either:
            
            * There are no parameters in the sudo specification, it succeeds.
            * There are parameters, but ends in a start, we succeed (doesn't
              guarantee successful shell, but is more likely)
            * Parameters match exactly
        """

        if not "shell" in self.data:
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
            need = [
                self.resolve_binaries(n, shell=shell_path)
                for n in shlex.split(self.data["shell"])
            ]
            restricted = []
        else:
            # Needed and restricted parameters
            need = [
                self.resolve_binaries(n, shell=shell_path)
                for n in self.data["shell"].get("need", [])
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

    def read_file(self, file_path: str, sudo_prefix: str = None) -> str:
        """ Build a payload which will leak the contents of the specified file.
        """

        if "read_file" not in self.data:
            return None

        # path = quote(self.path)
        path = self.path
        if sudo_prefix:
            path = sudo_prefix + " " + path

        return self.resolve_binaries(
            self.data["read_file"], path=path, lfile=quote(file_path)
        )

    @property
    def has_read_file(self):
        """ Check if this binary has a read_file capability """
        try:
            result = self.read_file("test")
        except MissingBinary:
            return False
        return result is not None

    @property
    def has_write_stream(self):
        try:
            result = self.write_stream("test")
        except MissingBinary:
            return False
        return result is not None

    def write_stream(self, file_path, sudo_prefix: str = None) -> str:
        """ Build a payload which will write stdin to a file. """

        if "write_stream" not in self.data:
            return None

        path = self.path
        if sudo_prefix:
            path = sudo_prefix + " " + path

        if isinstance(self.data["write_stream"], str):
            command = self.data["write_stream"]
            input = None
        else:
            command = self.data["write_stream"].get("command", "{path}")
            input = self.data["write_stream"].get("input", None)

        command = self.resolve_binaries(command, path=path)
        if input is not None:
            input = self.resolve_binaries(input, path=path)

        return (command, input)

    def write_file(self, file_path: str, data: bytes, sudo_prefix: str = None) -> str:
        """ Build a payload to write the specified data into the file """

        if "write_file" not in self.data:
            return None

        # path = quote(self.path)
        path = self.path
        if sudo_prefix:
            path = sudo_prefix + " " + path

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

        return self.resolve_binaries(
            self.data["write_file"]["payload"],
            path=path,
            lfile=quote(file_path),
            data=quote(data.decode("utf-8")),
        )

    @property
    def has_write_file(self):
        """ Check if this binary has a write_file capability """
        try:
            result = self.write_file("test", "test")
        except MissingBinary:
            return False
        return result is not None

    @property
    def is_safe(self):
        """ Check if this binary has a write_file capability """
        return self.data.get("safe", True)

    def command(self, command: str) -> str:
        """ Build a payload to execute the specified command """

        if "command" not in self.data:
            return None

        return self.resolve_binaries(
            self.data["command"], path=self.path, command=quote(command)
        )

    @property
    def has_command(self):
        """ Check if this binary has a command capability """
        try:
            result = self.command("test")
        except MissingBinary:
            return False
        return result is not None

    @classmethod
    def load(cls, gtfo_path: str):
        with open(gtfo_path) as filp:
            cls._binaries = json.load(filp)

    @classmethod
    def find(cls, which: Callable, path: str = None, name: str = None) -> "Binary":
        """ Locate the given gtfobin and return the Binary object. If name is
        not given, it is assumed to be the basename of the path. """

        if name is None:
            name = os.path.basename(path)

        for binary in cls._binaries:
            if binary["name"] == name:
                return Binary(path, binary, which)

        return None

    @classmethod
    def find_capability(
        cls,
        which: Callable[[str], str],
        capability: int = Capability.ALL,
        safe: bool = False,
    ) -> "Binary":
        """ Locate the given gtfobin and return the Binary object. If name is
        not given, it is assumed to be the basename of the path. """

        for data in cls._binaries:
            path = which(data["name"], quote=True)
            if path is None:
                continue

            binary = Binary(path, data, which)
            if not binary.is_safe and safe:
                continue
            if (binary.capabilities & capability) == 0:
                continue

            return binary

    @classmethod
    def find_sudo(
        cls, spec: str, get_binary_path: Callable[[str], str], capability: int
    ) -> "Binary":
        """ Locate a GTFObin binary for the given sudo spec. This will separate 
        out the path of the binary from spec, and use `find` to locate a Binary
        object. If that binary cannot be used with this spec or no binary exists,
        SudoNotPossible is raised. shell_path is used as the default for specs
        which specify "ALL". """

        binaries = []

        if spec == "ALL":
            # If the spec specifies any command, we check each known gtfobins
            # binary for one usable w/ this sudo spec. We use recursion here,
            # but never more than a depth of one, so it should be safe.
            found_caps = 0

            while found_caps != capability:

                binary = cls.find_capability(
                    get_binary_path, (capability & ~found_caps)
                )

                if binary is None:
                    # raise SudoNotPossible("no available gtfobins for ALL")
                    break

                binaries.append(binary)
                found_caps |= binary.capabilities

        else:
            path = shlex.split(spec)[0]
            binary = cls.find(path)
            if binary is not None:
                found_caps = binary.capabilities & capability
                binaries = [binary]

        if len(binaries) == 0 or found_caps == 0:
            raise SudoNotPossible(f"no available gtfobins for {spec}")

        # for

        # This will throw an exception if we can't sudo with this binary
        # _ = binary.can_sudo(spec, "")

        # return spec, binary
        return binaries
