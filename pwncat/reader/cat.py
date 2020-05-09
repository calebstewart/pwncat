#!/usr/bin/env python3

from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style

from pwncat.util import info, success, error, progress, warn
from pwncat.reader.base import Method, ReaderError, Technique
from pwncat import gtfobins


class CatMethod(Method):

    name = "cat"
    BINARIES = ["cat"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(CatMethod, self).__init__(pty)

        # self.suid_paths = None

    # def find_suid(self):

    #     # Spawn a find command to locate the setuid binaries
    #     delim = self.pty.process("find / -perm -4000 -print 2>/dev/null")
    #     files = []
    #     self.suid_paths = {}

    #     while True:
    #         path = self.pty.recvuntil(b"\n").strip()
    #         progress("searching for setuid binaries")

    #         if delim in path:
    #             break

    #         files.append(path.decode("utf-8"))

    #     for path in files:
    #         user = (
    #             self.pty.run(f"stat -c '%U' {shlex.quote(path)}")
    #             .strip()
    #             .decode("utf-8")
    #         )
    #         if user not in self.suid_paths:
    #             self.suid_paths[user] = []
    #         self.suid_paths[user].append(path)

    def enumerate(self, filename: str) -> List[Technique]:
        """ Find all techniques known at this time """

        # if self.suid_paths is None:
        #     self.find_suid()

        binary = self.BINARIES[0]

        yield Technique(filename, self, binary)

        # for user, paths in self.suid_paths.items():
        #     for path in paths:
        #         binary = gtfobins.Binary.find(path)
        #         if binary is not None:

    def execute(self, technique: Technique):
        """ Run the specified technique """

        filename = technique.filename
        binary = technique.ident
        # enter, exit = binary.shell("/bin/bash")

        info(
            f"attempting read {Fore.YELLOW}{Style.BRIGHT}{filename}{Style.RESET_ALL} with {Fore.GREEN}{Style.BRIGHT}{binary}{Style.RESET_ALL}",
        )

        # before_shell_level = self.pty.run("echo $SHLVL").strip()
        # before_shell_level = int(before_shell_level) if before_shell_level != b"" else 0

        # Run the start commands
        delim = self.pty.process(f"{binary} {filename}", delim=True)

        content = self.pty.recvuntil(delim).split(delim)[0]
        # print(content)

        return content
        # sleep(0.1)
        # user = self.pty.run("whoami").strip().decode("utf-8")
        # if user == technique.user:
        #     success("privesc succeeded")
        #     return exit
        # else:
        #     error(f"privesc failed (still {user} looking for {technique.user})")
        #     after_shell_level = self.pty.run("echo $SHLVL").strip()
        #     after_shell_level = (
        #         int(after_shell_level) if after_shell_level != b"" else 0
        #     )
        #     if after_shell_level > before_shell_level:
        #         info("exiting spawned inner shell")
        #         self.pty.run(exit, wait=False)  # here be dragons

        # raise PrivescError(f"escalation failed for {technique}")

    def get_name(self, tech: Technique):
        return f"{Fore.GREEN}{tech.filename}{Fore.RESET} via {Fore.CYAN}{tech.ident}{Fore.RESET} ({Fore.RED}cat{Fore.RESET})"
