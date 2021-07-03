Listeners
=========

The ``listeners`` command is used to manager active and stopped listeners. This command provides the capability to view listener configuration, stop active listeners, view failure messages, and initialize queued channels.

When initializing a channel, you will be shown a list of pending channels, of which you can select and define a platform name. After specifying a platform, a session will be established with the channel and you will have the option of initializing other queue channels.

.. code-block:: bash
    :caption: Interacting with Listeners

    # List only running and failed listeners
    listeners
    # List all listeners (running, stopped, and failed)
    listeners --all
    # Kill listener with ID 0
    listeners -k 0
    # View listener configuration (and failure message)
    listeners 0
    # Initialize pending channels
    listeners --init 0
