Developing Extensions
=====================

There are two ways to extend the pwncat platform: commands and modules. Commands
are things like ``run``, ``escalate`` and ``set``. They operate on the manager
instance, and do not require a connected session. On the other hand, modules are
things like ``implant.authorized_key`` and ``enumerate.user``. They operate on
specific connected instances.

Commands must be implemented in the pwncat source structure as modules under
``pwncat/commands/``. Each command exists in it's own source file as a class
named ``Command`` which inherits from ``BaseCommand`` class.

Modules can either be implemented under ``pwncat/modules/`` or in a custom
directory loaded with the ``load`` command (e.g. in your configuration script).
Each module resides in it's own source file and is defined by a class named
``Module`` and inherits from the class ``BaseModule``. Modules must define an
expected platform.

.. toctree::
   :caption: Contents

   modules.rst
   commands.rst
