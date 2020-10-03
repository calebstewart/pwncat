Use
===

The ``use`` command can be *used* to enter the context of a module. When
within a module context, the ``run``, ``set`` and ``info`` commands operate
off of the module currently in the context.

The use command simply takes the name of the module you would like to use
and takes no other arguments or flags.

.. code-block:: bash

   # Enter the context of the `enumerate.gather` module
   use enumerate.gather
   # Get information/help for this module
   info
   # Run the module
   run
