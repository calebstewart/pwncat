#!/usr/bin/env python3
from typing import List

from pwncat.util import console
from rich.prompt import Prompt
from pwncat.facts import Implant, ImplantType
from pwncat.modules import Bool, Status, Argument, BaseModule, ModuleFailed


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

    """ Defines where this implant module is useful (either remote
    connection or local escalation or both). This also identifies a
    given implant module as applying to "all users" """
    ARGUMENTS = {}
    """ The default arguments for any persistence module. If other
    arguments are specified in sub-classes, these must also be
    included to ensure compatibility across persistence modules. """
    COLLAPSE_RESULT = True
    """ The ``run`` method returns a single scalar value even though
    it utilizes a generator to provide status updates. """

    def run(self, session: "pwncat.manager.Session", **kwargs):
        """This method should not be overriden by subclasses. It handles all logic
        for installation, escalation, connection, and removal. The standard interface
        of this method allows abstract interactions across all persistence modules."""

        yield Status(f"installing implant")
        implant = yield from self.install(session, **kwargs)

        # Register the installed implant as an enumerable fact
        session.register_fact(implant)

        # Update the database
        session.db.transaction_manager.commit()

        # Return the implant
        return implant

    def install(self, **kwargs):
        """
        Install the implant on the target host and return a new implant instance.
        The implant will be automatically added to the database. Arguments aside
        from `remove` and `escalate` are passed directly to the install method.

        :param user: the user to install persistence as. In the case of ALL_USERS persistence, this should be ignored.
        :type user: str
        :param kwargs: Any custom arguments defined in your ``ARGUMENTS`` dictionary.
        :raises ModuleFailed: installation failed.
        """
        raise NotImplementedError
