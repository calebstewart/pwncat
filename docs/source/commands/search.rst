Search
======

This command allows you to search for relevant modules which are currently imported
into pwncat. This performs a glob-based search and provides an ellipsized
description and module name in a nice table. The syntax is simple:

.. code-block:: bash

   # Search for modules under the `enumerate` package
   (local) pwncat$ search enumerate.*
