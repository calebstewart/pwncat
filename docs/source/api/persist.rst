Persistence Methods
===================

Persistence methods are implemented through an abstract ``PersistenceMethod`` base class which defines methods
for installing and removing various persistence methods. The persistence module and associated base classes
are defined in the ``pwncat/persist/__init__.py`` script.

Persistence methods are loaded using the ``pkgutil`` python module automatically from the ``pwncat/persist``
subdirectory. Any module implementing a ``Method`` class which inherits from the ``PersistenceMethod``
base class will be imported as an available persistence method.

Implementing Persistence Methods
--------------------------------

A persistence method is implemented by creating a new script under the ``pwncat/persist`` directory
which implements a ``Method`` class. This class must inherit from the ``PersistenceMethod`` base
class and implement the ``install`` and ``remove`` functions.

A privilege escalation method also defines a few properties as class variables which govern how
the method is utilized by ``pwncat``. The ``system`` variable is a boolean defining whether this
persistence method allows access only as ``root`` or is installed on a per-user basis. If this
item is true, all ``user`` options in further methods are ignored.

The ``name`` variable is used to create user-readable formatted strings representing this persistence
method. Lastly, the ``local`` variable is a boolean defining whether the persistence method allows
local escalation to the specified user.

Three methods can be overridden within the ``PersistenceMethod`` base class. The first is the ``install``
method. This method takes a ``user`` parameter (if not a system method), and should install persistence
as the specified user. If there is a problem or error during installation, ``PersistenceError`` should
be raised with a description of the error.

Next, the ``remove`` method must be implemented to undo the actions of the ``install`` method. It takes
the same ``user`` argument, and upon error should also raise ``PersistenceError``.

Lastly, the ``escalate`` method is only required if ``local`` is true. It should leverage this
persistence method to gain access shell access as the specified user (again, user should be ignored
for system methods). This is used as a shortcut in the implementation of the ``privesc`` command
to utilize local persistence methods to escalate to different users.

Locating and Installing Persistence Methods
-------------------------------------------

If you would like to programmatically install, remove or locate privilege escalation methods,
you can use the ``pwncat.victim.persist`` module. This module provides a generic interface
to enumerate available methods, list installed methods, and locate methods by name.

The ``install`` method takes a method name and an optional user. This will locate the identified
method and call it's ``install`` routine. If installation is successful, it will register the
method in the database as installed and also register a corresponding tamper object to track
the installation. If the method does not exist or failed to install, a ``PersistenceError``
exception is raised.

The ``register`` method takes the same parameters as the ``install`` method. It will register the
specified method as being installed but not perform the installation routine. This is useful
when a module installs a persistence method in a non-standard way and needs to register this
installation with the framework. For example, the ``privesc`` module may install SSH authorized
keys via a privesc file writer. If this happens, it will register this persistence with the ``persist``
module for tracking.

The ``remove`` is the inverse of the ``install`` method, and will completely remove the given
persistence method.

To find a persistence method by name, you can use the ``find`` method which returns an iterator
of known persistence methods. The  ``persist`` module is also an iterator which will yield all
known persistence methods.

The Persistence Module Class
----------------------------

.. autoclass:: pwncat.persist.Persistence
    :members:

The Base Persistence Method Class
---------------------------------

.. autoclass:: pwncat.persist.PersistenceMethod
    :members:
