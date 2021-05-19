#!/usr/bin/env python3
import enum
import socket
import inspect

import pwncat
import pwncat.db
from pwncat.util import State
from pwncat.modules import (
    Bool,
    Status,
    Argument,
    BaseModule,
    PersistType,
    ModuleFailed,
    PersistError,
    ArgumentFormatError,
)


def host_type(ident: str):
    return ident


class ImplantModule(BaseModule):
    """
    Base class for all persistence modules.

    Persistence modules should inherit from this class, and implement
    the ``install``, ``remove``, and ``escalate`` methods. All modules must
    take a ``user`` argument. If the module is a "system" module, and
    can only be installed as root, then an error should be raised for
    any "user" that is not root.

    If you need your own arguments to a module, you can define your
    arguments like this:

    .. code-block:: python

        ARGUMENTS = {
            **PersistModule.ARGUMENTS,
            "your_arg": Argument(str)
        }

    All arguments **must** be picklable. They are stored in the database
    as a SQLAlchemy PickleType containing a dictionary of name-value
    pairs.

    """

    TYPE: PersistType = PersistType.LOCAL
    """ Defines where this persistence module is useful (either remote
    connection or local escalation or both). This also identifies a
    given persistence module as applying to "all users" """
    ARGUMENTS = {
        "host": Argument(
            host_type,
            help="Host ID, IP address, Hostname or Host object (default: current)",
        ),
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
    """ The default arguments for any persistence module. If other
    arguments are specified in sub-classes, these must also be
    included to ensure compatibility across persistence modules. """
    COLLAPSE_RESULT = True
    """ The ``run`` method returns a single scalar value even though
    it utilizes a generator to provide status updates. """

    def __init__(self):
        super(PersistModule, self).__init__()

        if PersistType.ALL_USERS in self.TYPE:
            self.ARGUMENTS["user"].default = None
            self.ARGUMENTS[
                "user"
            ].help = "Ignored for install/remove. Defaults to root for escalate."

    def run(self, remove, escalate, connect, host, **kwargs):
        """This method should not be overriden by subclasses. It handles all logic
        for installation, escalation, connection, and removal. The standard interface
        of this method allows abstract interactions across all persistence modules."""

        if "user" not in kwargs:
            raise RuntimeError(f"{self.__class__} must take a user argument")

        if pwncat.victim is not None and connect:
            raise PersistError("cannot connect when a session is active")

        if not connect and pwncat.victim.host.id != host.id:
            raise PersistError(
                "cannot modify persistence of host without an active session"
            )

        # We need to clear the user for ALL_USERS modules,
        # but it may be needed for escalate.
        requested_user = kwargs["user"]
        if PersistType.ALL_USERS in self.TYPE:
            kwargs["user"] = None

        # Check if this module has been installed with the same arguments before
        row = (
            get_session()
            .query(pwncat.db.Persistence)
            .filter_by(host_id=host.id, method=self.name, args=kwargs)
            .first()
        )

        # Remove this module
        if row is not None and remove:
            # Run module-specific cleanup
            result = self.remove(**kwargs)
            if inspect.isgenerator(result):
                yield from result
            else:
                yield result

            # Remove from the database
            get_session().query(pwncat.db.Persistence).filter_by(
                host_id=pwncat.victim.host.id, method=self.name, args=kwargs
            ).delete(synchronize_session=False)
            return
        elif row is not None and escalate:
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
        elif row is not None and connect:
            if requested_user is None:
                kwargs["user"] = "root"
            else:
                kwargs["user"] = requested_user
            result = self.connect(host, **kwargs)
            if inspect.isgenerator(result):
                yield from result
            else:
                yield result
            return
        elif row is None and (remove or escalate or connect):
            raise PersistError(f"{self.name}: not installed with these arguments")
        elif row is not None:
            yield Status(f"{self.name}: already installed with matching arguments")
            return

        # Let the installer also produce results
        result = self.install(**kwargs)
        if inspect.isgenerator(result):
            yield from result
        elif result is not None:
            yield result

        self.register(kwargs)

    def register(self, **kwargs):
        """
        Register a module as installed, even if it wasn't installed by
        the bundled ``install`` method. This is mainly used during escalation
        when a standard persistence method is installed manually through
        escalation file read/write.
        """

        if "user" not in kwargs:
            raise RuntimeError(f"{self.__class__} must take a user argument")

        # Register this persistence module in the database
        row = pwncat.db.Persistence(
            host_id=pwncat.victim.host.id,
            method=self.name,
            user=kwargs["user"],
            args=kwargs,
        )
        pwncat.victim.host.persistence.append(row)

        get_session().commit()

    def install(self, **kwargs):
        """
        Install this persistence module on the victim host.

        :param user: the user to install persistence as. In the case of ALL_USERS persistence, this should be ignored.
        :type user: str
        :param kwargs: Any custom arguments defined in your ``ARGUMENTS`` dictionary.
        :raises PersistError: All errors must be PersistError or a subclass thereof.

        """
        raise NotImplementedError

    def remove(self, **kwargs):
        """
        Remove this persistence module from the victim host.

        :param user: the user to install persistence as. In the case of ALL_USERS persistence, this should be ignored.
        :type user: str
        :param kwargs: Any custom arguments defined in your ``ARGUMENTS`` dictionary.
        :raises PersistError: All errors must be PersistError or a subclass thereof.

        """
        raise NotImplementedError

    def escalate(self, **kwargs):
        """
        Escalate locally from the current user to another user by
        using this persistence module.

        :param user: the user to install persistence as. In the case of ALL_USERS persistence, this should be ignored.
        :type user: str
        :param kwargs: Any custom arguments defined in your ``ARGUMENTS`` dictionary.
        :raises PersistError: All errors must be PersistError or a subclass thereof.

        """
        raise NotImplementedError

    def connect(self, host, **kwargs) -> socket.SocketType:
        """
        Connect to a victim host by utilizing this persistence
        module. The host address can be found in the ``pwncat.victim.host``
        object.

        :param host: the host to connect to
        :type host: pwncat.db.Host
        :param user: the user to install persistence as. In the case of ALL_USERS persistence, this should be ignored.
        :type user: str
        :param kwargs: Any custom arguments defined in your ``ARGUMENTS`` dictionary.
        :rtype: socket.SocketType
        :return: An open channel to the victim
        :raises PersistError: All errors must be PersistError or a subclass thereof.

        """
        raise NotImplementedError
