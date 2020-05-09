#!/usr/bin/env python3
from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style
from io import StringIO

from pwncat.util import info, success, error, progress, warn, CTRL_C
from pwncat.privesc.base import Method, PrivescError, Technique

from pwncat.pysudoers import Sudoers


class SudoMethod(Method):

    name = "sudo"
    BINARIES = ["sudo"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(SudoMethod, self).__init__(pty)

        self.sudo_rules = None

    def find_sudo(self):

        self.pty.current_user["password"] = "password"
        current_user = self.pty.current_user

        # Process the prompt but it will not wait for the end of the output
        # delim = self.pty.process("sudo -l", delim=True)
        delim = self.pty.process("sudo -p 'Password: ' -l", delim=True)
        output = self.pty.client.recv(6).lower()

        if output == b"[sudo]" or output == b"passwo":
            info("sudo is asking for a password", overlay=True)

            if current_user["password"] is None:
                self.pty.client.send(CTRL_C)  # break out of password prompt
                raise PrivescError(
                    f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} has no known password"
                )

            # Reset the timeout to allow for sudo to pause
            old_timeout = self.pty.client.gettimeout()
            self.pty.client.settimeout(5)
            self.pty.client.send(current_user["password"].encode("utf-8") + b"\n")

            # Flush the rest of the password prompt
            self.pty.recvuntil("\n")

            # Check the output once more
            output = self.pty.client.recv(6).lower()

            # Reset the timeout to the originl value
            self.pty.client.settimeout(old_timeout)

            if (
                output == b"[sudo]"
                or output == b"passwo"
                or output == b"sorry,"
                or output == b"sudo: "
            ):
                self.pty.client.send(CTRL_C)  # break out of password prompt

                # Handle the edge case sudo telling us something
                if output == b"sorry,":
                    # Check if this user cannot run sudo
                    sudo_response = self.pty.recvuntil("\n").lower()

                    if b"may not run sudo" in sudo_response:

                        # Flush all the output
                        self.pty.recvuntil(delim)
                        raise PrivescError(
                            f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} may not run sudo"
                        )

                # Flush all the output
                self.pty.recvuntil(delim)
                raise PrivescError(
                    f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} seemingly has an incorrect password"
                )

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

        """

        for each rule
            have a function that maps a command to a GTFObins action
            for each user
                if user is ALL:
                    yield technique with root
                else:
                    yield a technique


        First look for things with NOPASSWD
        If there are no NOPASSWD set and you have no password known, then fail

        Then look for ALL, if there are any ALL and you DO know a password,
        pick the first of the list of the GTFObins commands that actually resolve with which

        For all others, check the command set it specifies, and if they overlap with the 
        GTFObins list, then yield those

        Anything that specifies specific users, yield a technique with each user

        """

    def enumerate(self) -> List[Technique]:
        """ Find all techniques known at this time """

        info(f"checking {Fore.YELLOW}sudo -l{Fore.RESET} output", overlay=True)
        if self.sudo_rules is None:
            self.sudo_rules = self.find_sudo()

        if not self.sudo_rules:
            return []

        sudo_no_password = []
        sudo_all_users = []
        sudo_other_commands = []

        for rule in self.sudo_rules:
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

                    success(
                        f"user {Fore.GREEN}{current_user['name']}{Fore.RESET} can run "
                        + f"{Fore.YELLOW}{command}{Fore.RESET} "
                        + f"as user {Fore.BLUE}{run_as_user}{Fore.RESET} "
                        + f"with {Fore.BLUE}{tag}{Fore.RESET}"
                    )

                if "NOPASSWD" in tag:
                    sudo_no_password.append(
                        {"run_as_user": run_as_user, "command": command}
                    )

                if "ALL" in run_as_user:
                    sudo_all_users.append({"run_as_user": "root", "command": command})

                else:
                    sudo_other_commands.append(
                        {"run_as_user": run_as_user, "command": command}
                    )

        return

        # yield Technique(user, self, (path, name, cmd))
        # return

    def execute(self, technique: Technique):
        """ Run the specified technique """

        path, name, commands = technique.ident

        info(
            f"attempting potential privesc with {Fore.GREEN}{Style.BRIGHT}{path}{Style.RESET_ALL}",
        )

        before_shell_level = self.pty.run("echo $SHLVL").strip()
        before_shell_level = int(before_shell_level) if before_shell_level != b"" else 0
        return
        # # Run the start commands
        # self.pty.run(commands[0].format(path) + "\n")

        # # sleep(0.1)
        # user = self.pty.run("whoami").strip().decode("utf-8")
        # if user == technique.user:
        #     success("privesc succeeded")
        #     return commands[1]
        # else:
        #     error(f"privesc failed (still {user} looking for {technique.user})")
        #     after_shell_level = self.pty.run("echo $SHLVL").strip()
        #     after_shell_level = (
        #         int(after_shell_level) if after_shell_level != b"" else 0
        #     )
        #     if after_shell_level > before_shell_level:
        #         info("exiting spawned inner shell")
        #         self.pty.run(commands[1], wait=False)  # here be dragons

        # raise PrivescError(f"escalation failed for {technique}")
