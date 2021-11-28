lcd
===

The ``lcwd`` command allows you to change the *local* working directory of the running
pwncat instance. This effects any command which interacts with the local filesystem (
e.g. ``upload`` and ``download``).

.. code-block:: bash

   # Example from @DanaEpp :P
   lcd ~/engagements/client_some_gawd_aweful_guid/host_abc/loot
   # Now, the following downloads will end up in the above directory
   download /path/to/some/loot
   download /paht/to/some/other/loot
