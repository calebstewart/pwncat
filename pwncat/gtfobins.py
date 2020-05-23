#!/usr/bin/env python3
from typing import Dict, Callable, Any, List, Generator, BinaryIO, IO, Tuple
from enum import Enum, Flag, auto
from base64io import Base64IO
import commentjson as json
import shlex
import os
import io


class ControlCodes:
    CTRL_C = "\x03"
    CTRL_X = "\x18"
    CTRL_Z = "\x1a"
    CTRL_D = "\x04"
    ESCAPE = "\x1B"


class SudoNotPossible(Exception):
    """ The given sudo command spec is not compatible with the method attempted. """


class MissingBinary(Exception):
    """ A method required an external binary that didn't exist """


class BinaryNotFound(Exception):
    """ The binary asked for either doesn't provided the required functionality
    or isn't present on the remote system """


class Capability(Flag):
    """ The capabilities of a given GTFOBin Binary. A binary may have multiple
    implementations of each capability, but these flags indicate a list of all
    capabilities which a given binary supports. """

    READ = auto()
    """ File read """
    WRITE = auto()
    """ File write """
    SHELL = auto()
    """ Shell access """

    ALL = READ | SHELL | WRITE
    """ All capabilities, used for iter_* methods """
    NONE = 0
    """ No capabilities. Should never happen. """


class Stream(Flag):
    """ What time of streaming data is required for a specific method.
    """

    RAW = auto()
    """ A raw, unencoded stream of data. If writing, this mode requires
    a ``length`` parameter to indicate how many bytes of data to transfer. """
    PRINT = auto()
    """ Supports reading/writing printable data only """
    HEX = auto()
    """ Supports reading/writing hex-encoded data """
    BASE64 = auto()
    """ Supports reading/writing base64 data """
    ANY = RAW | PRINT | HEX | BASE64
    """ Used with the iter_* methods. Shortcut for searching for any stream """
    NONE = 0
    """ No stream method. Should never happen. """


class Method:
    """ Abstract method class built from the JSON database """

    def __init__(self, binary: "Binary", cap: Capability, data: Dict[str, Any]):
        """ Create a new method associated with the given binary. """

        try:
            self.stream = Stream._member_map_[data.get("stream", "PRINT").upper()]
        except KeyError:
            raise ValueError(f"invalid stream specifier: {data['stream']}")

        self.binary = binary
        self.payload = data.get("payload", "{command}")
        self.args = data.get("args", [])
        self.suid = data.get("suid", None)
        self.input = data.get("input", "")
        self.exit = data.get("exit", "")
        self.restricted = data.get("restricted", [])
        self.cap = cap

    def sudo_args(self, binary_path: str, spec: str) -> bool:
        """ Check if this method is compatible with the given sudo command spec.
        It will evaluate whether there are wildcards, or if the given parameters
        satisfy the parameters needed for this method. The method returns the list
        of arguments that need to be added_lines to the sudo spec in order for it to
        run this method. 

        If this method is incompatible with the given sudo spec, SudoNotPossible
        is raised. If this spec is compatible, a list of arguments which need to
        be appended to the spec is returned.
        """

        if spec == "ALL":
            # We can run anything, so just return all arguments
            return binary_path, self.args

        # Split the sudo command specification
        args = shlex.split(spec.rstrip("*"))

        # There was a " *" which is not a wildcard
        if shlex.split(spec)[-1] == "*":
            has_wildcard = False
            args.append("*")
            command = spec
        elif spec[-1] == "*":
            has_wildcard = True
            command = spec.rstrip("*")

        # The sudo command is just "/path/to/binary", we are allowed to add any
        # parameters we want.
        if len(args) == 1 and spec[-1] != " ":
            return args[0], self.args

        # Check for disallowed arguments
        for arg in args:
            if arg in self.restricted:
                raise SudoNotPossible

        # Check if we already have the parameters we need
        needed = {k: False for k in self.args}
        for arg in args:
            if arg in needed:
                needed[arg] = True

        # Check if we have any missing needed parameters, and no wildcard
        # was given
        if any([not v for _, v in needed.items()]) and not has_wildcard:
            raise SudoNotPossible

        # Either we have all the arguments we need, or we have a wildcard
        return command, [k for k, v in needed.items() if not v]

    def build_payload(
        self,
        binary_path: str,
        spec: str = None,
        user: str = None,
        suid: bool = False,
        **kwargs,
    ) -> str:
        """ Generate a read payload """

        # Make sure both sudo_spec and sudo_user are provided if sudo_spec is
        assert spec is None or (spec is not None and user is not None)

        # Make sure we can use this spec, and get remainig arguments
        if spec is not None:
            command, args = self.sudo_args(binary_path, spec)
            args = self.binary.gtfo.resolve_binaries(
                " ".join(args),
                ctrl_c=ControlCodes.CTRL_C,
                ctrl_z=ControlCodes.CTRL_Z,
                ctrl_x=ControlCodes.CTRL_X,
                escape=ControlCodes.ESCAPE,
                ctrl_d=ControlCodes.CTRL_D,
                **kwargs,
            )
            command = f"sudo -u {user} " + command + " " + args
        else:
            if suid and self.suid:
                args = self.suid
            else:
                args = []
            args += self.args if self.args else []
            command = " ".join([binary_path, *args])
            # Resolve variables in the command/args
            command = self.binary.gtfo.resolve_binaries(
                command,
                ctrl_c=ControlCodes.CTRL_C,
                ctrl_z=ControlCodes.CTRL_Z,
                ctrl_x=ControlCodes.CTRL_X,
                escape=ControlCodes.ESCAPE,
                ctrl_d=ControlCodes.CTRL_D,
                **kwargs,
            )

        # Generate the main payload
        payload = self.binary.gtfo.resolve_binaries(
            self.payload,
            command=command,
            ctrl_c=ControlCodes.CTRL_C,
            ctrl_x=ControlCodes.CTRL_X,
            ctrl_z=ControlCodes.CTRL_Z,
            escape=ControlCodes.ESCAPE,
            ctrl_d=ControlCodes.CTRL_D,
            **kwargs,
        )

        return payload


class MethodWrapper:
    """
    Wraps a method and full binary path pair which together are capable of
    generating a payload to perform the specified capability.
    
    """

    def __init__(self, method: Method, binary_path: str):
        """ Create a Method Wrapper which references a specific binary path. 
        and method arguments. """
        self.binary_path = binary_path
        self.method = method

    def wrap_stream(self, pipe: BinaryIO) -> IO:
        """ Wrap the given BinaryIO pipe with the appropriate stream wrapper
        for this method. For "RAW" or "PRINT" streams, this is a null wrapper.
        For BASE64 and HEX streams, this will automatically decode the data as
        it is streamed. Closing the wrapper will automatically close the underlying
        pipe. """

        if self.stream is Stream.RAW or self.stream is Stream.PRINT:
            return pipe
        elif self.stream is not Stream.BASE64:
            raise RuntimeError(
                f"{self.stream.name}: we haven't implemented streaming of encodings besides base64"
            )

        wrapped = Base64IO(pipe)
        original_close = wrapped.close
        original_write = wrapped.write

        def close_wrapper():
            """ This is a dirty hack because Base64IO doesn't close the underlying
            stream when it closes. We want to assume this, so we wrap the function
            with one that will close the underlying stream. We need to close
            the Base64IO stream first, since data may be waiting to get decoded
            and sent. """
            original_close()
            pipe.close()

        def write_wrapper(data: bytes):
            """ This is another nasty hack. The underlying Base64IO object 
            erroneously returns the number of base64 bytes written, not the number
            if source bytes written. This causes other Python IO classes to raise
            an exception. We know our underlying socket will block on sending
            data, so all data will be sent. Again, this is gross, but it makes
            the python stdlib happy. """
            n = original_write(data)
            return min(len(data), (n * 3) // 4)

        wrapped.close = close_wrapper
        wrapped.write = write_wrapper
        # We want this, but it may cause issues
        wrapped.name = pipe.name

        return wrapped

    def build(self, **kwargs) -> Tuple[str, str, str]:
        """ Build the payload for this method and binary path. Depending on
        capability and stream type, different named parameters are required.
        
        """
        return self.payload(**kwargs), self.input(**kwargs), self.exit(**kwargs)

    def payload(self, **kwargs) -> str:
        return self.method.build_payload(self.binary_path, **kwargs)

    def exit(self, **kwargs) -> str:
        original = self.method.binary.gtfo.resolve_binaries(
            self.method.exit,
            ctrl_c=ControlCodes.CTRL_C,
            ctrl_z=ControlCodes.CTRL_Z,
            ctrl_x=ControlCodes.CTRL_X,
            escape=ControlCodes.ESCAPE,
            ctrl_d=ControlCodes.CTRL_D,
            **kwargs,
        )

        if original == "" and Capability.SHELL in self.cap:
            original = "exit\n"

        return original

    def input(self, **kwargs) -> str:
        return self.method.binary.gtfo.resolve_binaries(
            self.method.input,
            ctrl_c=ControlCodes.CTRL_C,
            ctrl_z=ControlCodes.CTRL_Z,
            ctrl_x=ControlCodes.CTRL_X,
            escape=ControlCodes.ESCAPE,
            ctrl_d=ControlCodes.CTRL_D,
            **kwargs,
        )

    @property
    def stream(self) -> Stream:
        """ Access this methods stream type """
        return self.method.stream

    @property
    def cap(self) -> Capability:
        """ Access this methods capabilities """
        return self.method.cap


class Binary:
    """ Encapsulates a GTFOBin and it's methods for all capabilities """

    def __init__(self, gtfo: "GTFOBins", name: str, methods: List[Dict[str, Any]]):
        """ Create a GTFOBin from the given list of capabilities """

        # Initialize to no capabilities
        self.gtfo = gtfo
        self.caps = Capability.NONE
        self.methods: List[Method] = []

        for method_data in methods:
            try:
                method_cap = Capability._member_map_[
                    method_data.get("type", "WRONG").upper()
                ]
            except KeyError:
                raise RuntimeError(f"invalid method type for {name}")

            method = Method(self, method_cap, method_data)
            self.methods.append(method)
            self.caps |= method_cap

    def iter_methods(
        self, binary_path: str, caps: Capability, stream: Stream, spec: str = None
    ):
        """ Iterate over methods in this binary matching the capability and stream
        masks """

        # Only yield results with overlapping capabilities
        if not (self.caps & caps):
            return

        for method in self.methods:
            # Ensure this method implements a requested capability
            if method.cap not in caps:
                continue
            # If we specified stream, make sure it matches
            if stream is not None and method.stream not in stream:
                continue
            # Ensure this method is capable of sudo with this spec
            try:
                if spec is not None:
                    method.sudo_args(binary_path, spec)
            except SudoNotPossible:
                continue

            try:
                yield MethodWrapper(method, binary_path)
            except (SudoNotPossible, MissingBinary):
                continue


class GTFOBins:
    """
    Wrapper around the GTFOBins database. Provides access to searching for methods
    of performing various capabilities generically. All iterations yield MethodWrapper
    objects.
    
    :param gtfobins: path to the gtfobins database
    :type gtfobins: str
    :param which: a callable which resolves binary basenames to full paths. A second
        parameter indicates whether the returned path should be quoted as with shlex.quote.
    :type which: Callable[[str, Optional[bool]], str]
    """

    def __init__(self, gtfobins: str, which: Callable[[str], str]):
        """ Create a new GTFOBins object. This will load the JSON gtfobins data
        file specified in the `gtfobins` parameter. The `which` method is
        remembered to lookup existing binaries on the target system for later. """

        self.which = which
        self.binaries: Dict[str, Binary] = {}

        with open(gtfobins, "r") as filp:
            binary_data = json.load(filp)

        if not isinstance(binary_data, dict):
            raise ValueError("invalid gtfobins.json format (expecting dict)")

        self.parse_binary_data(binary_data)

    def parse_binary_data(self, binary_data: Dict[str, List[Dict[str, Any]]]):
        """ Parse the given GTFObins binary information into the associated
        in-memory binary objects """

        for name, data in binary_data.items():
            binary = Binary(self, name, data)
            self.binaries[name] = binary

    def iter_sudo(
        self,
        spec: str,
        caps: Capability = Capability.ALL,
        stream: Stream = None,
        **kwargs,
    ):
        """ Iterate over methods which are sudo-capable w/ the given sudo spec.
        This will restrict the search to those binaries which match the given sudo
        command spec. """

        if spec != "ALL":
            # This is the harder case. We have a specific specification for the
            # command wecan run.

            # If there are arguments, remove them and grab the first item, which
            # will be the path or binary name
            binary_path = shlex.split(spec.rstrip("*"))[0]

            for method in self.iter_binary(
                binary_path, caps, stream, spec=spec, **kwargs
            ):
                yield method
        else:
            # We can run any w/ this spec. This becomes the same as calling
            # iter_methods. "sudo_args" in "method" will notice this as well
            # and succeed for any command.
            yield from self.iter_methods(caps, stream, spec=spec, **kwargs)

    def find_binary(self, binary_path: str, caps: Capability = Capability.ALL):
        """ Locate a binary by name. Only return a binary if the capabilities
        overlap. Raise an BinaryNotFound exception if the capabilities don't
        match or the given binary doesn't exist on the remote system. """

        binary_name = os.path.basename(binary_path)
        if binary_name not in self.binaries:
            raise BinaryNotFound

        if not (self.binaries[binary_name].caps & caps):
            raise BinaryNotFound

        return self.binaries[binary_name]

    def iter_binary(
        self,
        binary_path: str,
        caps: Capability = Capability.ALL,
        stream: Stream = None,
        spec: str = None,
    ) -> Generator[MethodWrapper, None, None]:
        """ Iterate over methods for the given remote binary path. A binary will
        be located by taking the basename of the given path, and the cross-
        referencing with the given capabilities and stream types. """

        binary_name = os.path.basename(binary_path)
        if binary_name not in self.binaries:
            return

        yield from self.binaries[binary_name].iter_methods(
            binary_path, caps, stream, spec
        )

    def iter_methods(
        self,
        caps: Capability = Capability.ALL,
        stream: Stream = None,
        spec: str = None,
    ) -> Generator[MethodWrapper, None, None]:
        """ Iterate over methods which provide the given capabilities """

        for name, binary in self.binaries.items():
            path = self.which(name)

            # Only yield results applicable to the target system
            if path is None:
                continue

            yield from binary.iter_methods(path, caps, stream, spec)

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
