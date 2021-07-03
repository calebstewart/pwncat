Modules
=======

Modules allow ``pwncat`` to abstractly handle many different operations without
polluting the commands. Persistence, privilege escalation and enumeration are all
implemented as modules within ``pwncat``. The modules are dynamically loaded at
runtime. There is a set of default modules included with ``pwncat`` and also the
ability to load custom modules at runtime (either manually or via local or global
configuration script).

Module Contexts
---------------

You can enter a module "context" which means that any ``set`` commands will
operate specifically on that modules arguments by default. This is useful
when a module takes a large number of arguments or complex arguments. In
this case, the local prompt prefix changes to ``([module_name])`` vice
the normal ``(local)``. The context is exited automatically after using the
``run`` command.

When in a module context, commands like ``info`` and ``run`` no longer
require the module name as a parameter. It is inferred by the current context.

Locating Modules
----------------

Modules are located using the ``search`` command at the local prompt:

.. code-block:: bash

   search enumerate.*

Viewing Documentation
---------------------

Module documentation can be viewed with the ``info`` command. When within
a module context, the module name is inferred from the current context
if not specified.

.. code-block:: bash

   info escalate.auto

Running Modules
---------------

The ``run`` command is used to execute a module. The module name is inferred
from the module context if not specified. Key-value parameters can be specified
in the ``run`` command or with ``set`` within a module context.

.. code-block:: bash

   run escalate.auto user=root
   use escalate.auto
   set user root
   run
