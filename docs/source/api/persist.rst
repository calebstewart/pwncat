Persistence Modules
===================

Persistence modules are simply ``pwncat`` modules which inherit from the
``PersistModule`` base class. The ``PersistModule`` base class takes care
of the ``run`` method. The ``install`` and ``remove`` methods must be
implemented in all persistence modules. Depending on the type, at least
one of ``connect`` and ``escalate`` must be implemented.

Unlike a base module, persistence modules should raise the ``PersistError``
class when a module fails.

``pwncat/modules/persist/passwd.py`` is a good example of a persistence
module if you'd like to review a working module.

The ``install``, ``remove``, and ``escalate`` methods should be generators
which yield status updates during operation. Status updates should be of
the type ``pwncat.modules.Status`` which is a subclass of ``str``. Any other
values will be ignored.

Persistence Types
-----------------

Persistence types are defined by the ``TYPE`` module class property. This
property is a ``PersistType`` flags instance. There are three possible
persistence types as documented below. This field describes how an installed
module can be used. At least one of the listed types must be specified.


Custom Arguments
----------------

Custom arguments can be specified in the same way as a base module: the
``ARGUMENTS`` class property. The only difference is that you must include
the base persistence arguments in addition to new arguments. Every
persistence module takes the following arguments: "user", "remove", "escalate"
and "connect".

If custom arguments are used, the persistence module cannot be automatically
invoked by privilege escalation. This is not required, but you should be
aware during implementation/testing.

In addition to the ``user`` argument, all custom arguments are passed to
all module methods as keyword arguments with the same name as in the
``ARGUMENTS`` class property. The ``remove``, ``escalate`` and ``connect``
arguments are only received and processed by the the ``run`` method.

Simple Example Module
---------------------

This serves as a baseline persistence module. It doesn't do anything, but
show the structure of a working module.

.. code-block:: python

    class Module(PersistModule):
        """ This docstring will be used as the information from the ``info``
        command. """

        # PersistType.LOCAL requires the ``escalate`` method
        # PersistType.REMOTE requires the ``connect`` method
        TYPE = PersistType.LOCAL | PersistType.REMOTE
        # If no custom arguments are needed, this can be ommitted
        # completely.
        ARGUMENTS = {
            **PersistModule.ARGUMENTS,
            "custom_arg": Argument(str),
        }

        def install(self, user, custom_arg):
            """ Install the module on the victim """

            yield Status("Update the progress bar by yielding Status objects")

        def remove(self, user, custom_arg):
            """ Remove any modifications from the remote victim """

            yield Status("You can also update the progress bar here")

        def escalate(self, user, custom_arg):
            """ Locally escalate privileges with this module """

            yield Status("Update the status information")
            return "exit command used to leave this new shell"

        def connect(self, user, custom_arg):
            """ Connect to the victim at pwncat.victim.host.ip """

            # Return a socket-like object connected to the victim shell
            return socket.create_connection(pwncat.victim.host.ip)


Helper Classes
--------------

.. autoclass:: pwncat.modules.persist.PersistError

.. autoclass:: pwncat.modules.persist.PersistType
   :members:

Persistence Module Reference
----------------------------

.. autoclass:: pwncat.modules.persist.PersistModule
   :members:
