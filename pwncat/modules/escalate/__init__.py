#!/usr/bin/env python3
from typing import List, Dict
from io import BytesIO
import dataclasses

import pwncat
from pwncat.modules import (
    BaseModule,
    Argument,
    Status,
    Bool,
    Result,
    ArgumentFormatError,
)
from pwncat.gtfobins import Capability
from pwncat.file import RemoteBinaryPipe


class EscalateError(Exception):
    """ Indicates an error while attempting some escalation action """


@dataclasses.dataclass
class Technique:
    """ Describes a technique possible through some module.

    Modules should subclass this class in order to implement
    their techniques. Only the methods corresponding to the
    returned `caps` need be implemented.
    """

    caps: Capability
    """ What capabilities this technique provides """
    user: str
    """ The user this provides access as """
    module: "EscalateModule"
    """ The module which provides these capabilities """

    def write(self, filepath: str, data: bytes):
        raise NotImplementedError

    def read(self, filepath: str):
        raise NotImplementedError

    def exec(self, binary: str):
        raise NotImplementedError


@dataclasses.dataclass
class FileContentsResult(Result):
    """ Result which contains the contents of a file """

    filepath: str
    pipe: RemoteBinaryPipe
    data: bytes = None

    @property
    def category(self):
        return None

    @property
    def title(self):
        return f"Contents of {self.filepath}"

    @property
    def description(self):
        with self.stream:
            return self.stream.read().decode("utf-8")

    @property
    def stream(self):
        if self.pipe is not None:
            with self.pipe:
                self.data = self.pipe.read()
            self.pipe = None

        return BytesIO(self.data)


@dataclasses.dataclass
class EscalateResult(Result):
    """ The result of running an escalate module. This object contains
    all the enumerated techniques and provides an abstract way to employ
    the techniques to attempt privilege escalation.
    """

    techniques: Dict[str, List[Technique]]
    """ List of techniques available keyed by the user """

    @property
    def category(self):
        return None

    @property
    def title(self):
        return "Escalation Techniques"

    @property
    def description(self):
        cap_names = {
            Capability.READ: "file read",
            Capability.WRITE: "file write",
            Capability.SHELL: "shell",
        }

        result = []
        for technique in self.techniques:
            result.append(
                f"[magenta]{cap_names[technique.caps]}[/magenta] as [green]{technique.user}[/green] via {technique.module.name}"
            )

        return "\n".join(result)

    def extend(self, result: "EscalateResult"):
        """ Extend this result with another escalation enumeration result.
        This allows you to enumerate multiple modules and utilize all their
        techniques together to perform escalation. """
        for key, value in result.techniques:
            if key not in self.techniques:
                self.techniques[key] = value
            else:
                self.techniques[key].extend(value)

    def add(self, technique: Technique):
        """ Add a new technique to this result object """
        if technique.user not in self.techniques:
            self.techniques[technique.user] = [technique]
        else:
            self.techniques[technique.user].append(technique)

    def write(self, user: str, filepath: str, data: bytes):
        """ Attempt to use all the techniques enumerated to write to a file
        as the given user """

        if user not in self.techniques:
            raise EscalateError(f"file write as {user} not possible")

        # See if we can perform this action directly
        for technique in self.techniques[user]:
            if Capability.WRITE in technique.caps:
                try:
                    return technique.write(filepath, data)
                except EscalateError:
                    continue

        # Can't perform directly. Can we escalate to the user with a shell?
        try:
            exit_cmd = self.exec(user, shell="/bin/sh")
        except EscalateError:
            raise EscalateError(f"file write as {user} not possible")

        # We are now running in a shell as this user, just write the file
        try:
            with pwncat.victim.open(filepath, "w", length=len(data)) as filp:
                filp.write(data)
        except (PermissionError, FileNotFoundError):
            raise EscalateError(f"file write as {user} not possible")

        # Send the exit command to return to the previous user/undo what we
        # did to get here.
        pwncat.victim.client.send(exit_cmd)

    def read(self, user: str, filepath: str):
        """ Attempt to use all the techniques enumerated to read a file
        as the given user """

        if user not in self.techniques:
            raise EscalateError(f"file read as {user} not possible")

        # See if we can perform this action directly
        for technique in self.techniques[user]:
            if Capability.WRITE in technique.caps:
                try:
                    return technique.read(filepath)
                except EscalateError:
                    continue

        # Can't perform directly. Can we escalate to the user with a shell?
        try:
            exit_cmd = self.exec(user, shell="/bin/sh")
        except EscalateError:
            raise EscalateError(f"file read as {user} not possible")

        # We are now running in a shell as this user, just write the file
        try:
            filp = pwncat.victim.open(filepath, "r",)
            # Our exit command needs to be run as well when the file is
            # closed
            filp.exit_cmd += exit_cmd
            return filp
        except (PermissionError, FileNotFoundError):
            raise EscalateError(f"file read as {user} not possible")

    def exec(self, user: str, shell: str):
        """ Attempt to use all the techniques enumerated to execute a
        shell as the specified user """

        if user in self.techniques:
            for technique in self.techniques[user]:
                if Capability.SHELL in technique.caps:
                    try:
                        return technique.exec(shell)
                    except EscalateError:
                        continue

        raise EscalateError(f"exec as {user} not possible")


class EscalateModule(BaseModule):
    """ The base module for all escalation modules.

    I want using the escalate modules to look something like this:

    # Look for techniques but don't perform escalation
    run escalate.auto user=root
    # Escalate to root automatically (e.g. enumerate all modules)
    run escalate.auto exec user=root shell=/bin/bash
    # Write a file as another user
    run escalate.auto write user=root path=/root/.ssh/authorized_keys content=~/.ssh/id_rsa.pub
    # Read a file as another user
    run escalate.auto read user=root path=/etc/shadow

    That is all "auto" module stuff. However, each individual module
    should have the same interface. Individual modules may require or
    accept other arguments from the standard if needed. During auto
    escalation, modules that require extra parameters which aren't
    specified will be ignored. From a code perspective, I'd like
    interaction with these modules to look like this:

    # Retrieve a list of techniques from the module
    escalate = pwncat.modules.run("escalate.sudo")
    # This escalation result object has methods for performing
    # escalation, but also conforms to the `Result` interface
    # for easily displaying the results.
    escalate.exec("root", shell="/bin/bash")

    # The auto module can easily collect results from
    # multiple modules in order to build a more comprehensive
    # escalation primitive
    escalate = EscalateResult(techniques={})
    for module in modules:
        escalate.extend(module.run(**kwargs))
    escalate.exec("root", shell="/bin/bash")

    As with persistence modules, if you need extra arguments for a
    specialized escalation module, you should define your arguments like so:

    ARGUMENTS = {
        **EscalateModule.ARGUMENTS,
        "custom_arg": Argument(str)
    }

    """

    ARGUMENTS = {
        "user": Argument(
            str, default="root", help="The user you would like to escalate to"
        ),
        "exec": Argument(
            Bool, default=False, help="Attempt escalation only using this module"
        ),
        "write": Argument(
            Bool, default=False, help="Attempt to write a file using this module"
        ),
        "read": Argument(
            Bool, default=False, help="Attempt to read a file using this module"
        ),
        "shell": Argument(str, default="current", help="The shell to use for exec"),
        "path": Argument(str, default=None, help="The file to read/write"),
        "data": Argument(bytes, default=None, help="The data to write to a file"),
    }
    # This causes the BaseModule to collapse a single generator result
    # into it's value as opposed to returning a list with one entry.
    # This allows us to use `yield Status()` to update the progress
    # while still returning a single value
    COLLAPSE_RESULT = True

    def run(self, user, exec, read, write, shell, path, data, **kwargs):
        """ This method is not overriden by subclasses. Subclasses should
        override the `enumerate`, `write`, `read`, and `exec` methods.

        Running a module results in an EnumerateResult object which can be
        formatted by the default `run` command or used to execute various
        privilege escalation primitives utilizing the techniques enumerated.
        """

        if (exec + read + write) > 1:
            raise ArgumentFormatError(
                "only one of exec, read, and write may be specified"
            )

        if path is None and (read or write):
            raise ArgumentFormatError("path not specified for read/write")

        if data is None and write:
            raise ArgumentFormatError("data not specified for write")

        result = EscalateResult({})
        for technique in self.enumerate(**kwargs):
            yield Status(technique)
            result.add(technique)

        if exec:
            yield result.exec(user=user, shell=shell)
        elif read:
            filp = result.read(user=user, filepath=path)
            yield FileContentsResult(path, filp)
        elif write:
            yield result.write(user=user, filepath=path, data=data)
        else:
            yield result

    def enumerate(self, **kwargs):
        """ Enumerate techniques for this module which can perform the
        requested some of the requested capabilities. This should be
        a generator, and yield individual techniques. Techniques are
        self-contained objects which can perform the enumerated
        capabilities. """

        while False:
            yield None

        raise NotImplementedError
