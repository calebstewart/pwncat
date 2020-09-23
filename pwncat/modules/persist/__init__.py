#!/usr/bin/env python3
import enum
import inspect

import pwncat
import pwncat.db
from pwncat.util import State
from pwncat.modules import BaseModule, Argument, Bool, Status, ModuleFailed


class PersistError(ModuleFailed):
    """ There was a problem performing a persistence action """


class PersistType(enum.Flag):
    """
    The type of persistence we are installing. Local persistence only
    provides a method of persistence escalation from another user.
    Remote persistence allows us to re-establish C2 after disconnecting.

    Local persistence must implement the `escalate` method while remote
    persistence must implement the `connect` method.

    Persistence modules can be both Local and Remote (e.g. private key
    persistence when a local `ssh` client is available). You can simply
    bitwise OR these flags together to specify both.

    """

    LOCAL = enum.auto()
    REMOTE = enum.auto()
    ALL_USERS = enum.auto()


class PersistModule(BaseModule):
    """
    Base class for all persistence modules.

    Persistence modules should inherit from this class, and implement
    the `install`, `remove`, and `escalate` methods. All modules must
    take a `user` argument. If the module is a "system" module, and
    can only be installed as root, then an error should be raised for
    any "user" that is not root.

    If you need your own arguments to a module, you can define your
    arguments like this:

    ARGUMENTS = {
        **PersistModule.ARGUMENTS,
        "your_arg": Argument(str)
    }

    All arguments **must** be picklable. They are stored in the database
    as a SQLAlchemy PickleType containing a dictionary of name-value
    pairs.

    """

    TYPE = PersistType.LOCAL
    ARGUMENTS = {
        "user": Argument(str, help="The user to install persistence as"),
        "remove": Argument(
            Bool, default=False, help="Remove an installed module with these parameters"
        ),
        "escalate": Argument(
            Bool,
            default=False,
            help="Utilize this persistence module to escalate locally",
        ),
        "connect": Argument(
            Bool,
            default=False,
            help="Connect to a remote host with this module. Only valid from the connect command.",
        ),
    }
    COLLAPSE_RESULT = True

    def __init__(self):
        super(PersistModule, self).__init__()

        if PersistType.ALL_USERS in self.TYPE:
            self.ARGUMENTS["user"].default = None
            self.ARGUMENTS[
                "user"
            ].help = "Ignored for install/remove. Defaults to root for escalate."

    def run(self, remove, escalate, connect, **kwargs):

        if "user" not in kwargs:
            raise RuntimeError(f"{self.__class__} must take a user argument")

        # We need to clear the user for ALL_USERS modules,
        # but it may be needed for escalate.
        requested_user = kwargs["user"]
        if PersistType.ALL_USERS in self.TYPE:
            kwargs["user"] = None

        # Check if this module has been installed with the same arguments before
        ident = (
            pwncat.victim.session.query(pwncat.db.Persistence.id)
            .filter_by(host_id=pwncat.victim.host.id, method=self.name, args=kwargs)
            .scalar()
        )

        # Remove this module
        if ident is not None and remove:
            # Run module-specific cleanup
            result = self.remove(**kwargs)
            if inspect.isgenerator(result):
                yield from result
            else:
                yield result

            # Remove from the database
            pwncat.victim.session.query(pwncat.db.Persistence).filter_by(
                host_id=pwncat.victim.host.id, method=self.name, args=kwargs
            ).delete(synchronize_session=False)
            return
        elif ident is not None and escalate:
            # This only happens for ALL_USERS, so we assume they want root.
            if requested_user is None:
                kwargs["user"] = "root"
            else:
                kwargs["user"] = requested_user

            result = self.escalate(**kwargs)
            if inspect.isgenerator(result):
                yield from result
            else:
                yield result

            # There was no exception, so we assume it worked. Put the user
            # back in raw mode. This is a bad idea, since we may be running
            # escalate from a privesc context.
            # pwncat.victim.state = State.RAW
            return
        elif ident is not None and connect:
            if requested_user is None:
                kwargs["user"] = "root"
            else:
                kwargs["user"] = requested_user
            result = self.connect(**kwargs)
            if inspect.isgenerator(result):
                yield from result
            else:
                yield result
            return
        elif ident is None and (remove or escalate or connect):
            raise PersistError(f"{self.name}: not installed with these arguments")
        elif ident is not None:
            yield Status(f"{self.name}: already installed with matching arguments")
            return

        # Let the installer also produce results
        result = self.install(**kwargs)
        if inspect.isgenerator(result):
            yield from result
        elif result is not None:
            yield result

        # Register this persistence module in the database
        row = pwncat.db.Persistence(
            host_id=pwncat.victim.host.id,
            method=self.name,
            user=kwargs["user"],
            args=kwargs,
        )
        pwncat.victim.host.persistence.append(row)

        pwncat.victim.session.commit()

    def install(self, **kwargs):
        """ Install this persistence module """
        raise NotImplementedError

    def remove(self, **kwargs):
        """ Remove this persistence module """
        raise NotImplementedError

    def escalate(self, **kwargs):
        """ Perform local escalation with this persistence module """
        raise NotImplementedError

    def connect(self, **kwargs):
        """ Re-connect via this persistence module """
        raise NotImplementedError
