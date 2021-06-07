"""
pwncat supports abstract local and remote implants. Implants provide a way for
pwncat to either remotely reconnect or locally escalate privileges. Escalation
modules should be placed organizationally under the `implant/` package.

An implant module implements a single method named ``install`` and can take
any arbitrary arguments. The install method must return an :class:`Implant`
subclass. This class is what tracks implant installation, and allows for
triggering and removing the implant.

After installation, the :class:`Implant` object is added to the database
and can be located using the ``enumerate`` module and searching for
``implant.*`` fact types.

For examples of implant modules, see the ``pam`` and ``passwd`` built-in
implants located in ``pwncat/modules/linux/implant/``.
"""
from typing import List

from rich.prompt import Prompt

from pwncat.util import console
from pwncat.facts import Implant, ImplantType
from pwncat.modules import Bool, Status, Argument, BaseModule, ModuleFailed


class ImplantModule(BaseModule):
    """
    Base class for all implant modules.

    Implants must implement the :func:``install`` method and cannot
    override the :func:`run` method. The install method takes the same
    arguments as the standard :func:`run` method, including all your
    custom arguments.

    The install method must be a generator which yields :class:`Status`
    instances, and returns a :class:`Implant` object. Implant objects
    track the installed implant, and also provide methods for triggering,
    escalation and removal. Check the documentation for the :class:`Implant`
    class for more details.
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

        :param session: the session on which to operate
        :type session: pwncat.manager.Session
        :param kwargs: Any custom arguments defined in your ``ARGUMENTS`` dictionary.
        :raises ModuleFailed: installation failed.
        """
        raise NotImplementedError
