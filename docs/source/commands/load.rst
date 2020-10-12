Load
====

This command allows you to load custom ``pwncat`` modules from a python package.
The only parameter is the local path to a directory containing python packages
to load as modules.

``pwncat`` will load all modules under that package and search for classes named
``Module`` implementing the ``BaseModule`` base class. These modules will be named
based on the python package name relative to the specified directory. For example,
if you had a directory called ``.pwncat-modules`` with this structure::

    - .pwncat-modules/
        - enumerate/
            - __init__.py
            - custom.py
        - __init__.py

And a class named ``Module`` defined in ```custom.py`` then a new ``pwncat`` module
would be available under the name ``enumerate.custom``.

This command can be used in your configuration script to automatically load custom
modules at runtime.

.. code-block:: bash

   # Load modules from /home/user/.pwncat-modules
   (local) pwncat$ load /home/user/.pwncat-modules
   (local) pwncat$ run enumerate.custom
