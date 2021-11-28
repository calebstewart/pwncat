Listen
======

Create a new background listener to asynchronously establish sessions via a reverse shell payload. Background listeners can operate in two different modes: with a platform and without. If a platform type is not specified when creating a listener, channels will be queued within the listener until you initialize them with the ``listeners`` command.

Using the ``--drop-duplicate`` option will cause pwncat to drop any new sessions which duplicate both the target host and user of an existing session. This could be useful when using an infinite reverse shell implant.

Currently, listeners can only be used with the ``socket`` protocol, however listeners are capable of wrapping the socket server in an SSL context. A background listener can effectively replace the ``bind://`` and ``ssl-bind://`` protocols.

The ``--count`` option can be used to restrict background listeners to a set number of active sessions. After reaching the number specified by ``--count``, the listener will automatically be stopped.

.. code-block:: bash

    # Create a basic listener for linux sessions on port 9999
    listen -m linux 9999
    # Create an SSL listener for linux sessions on port 6666
    listen -m linux --ssl 9999
    # Create a listener with no platform which caches channels until initialization
    listen 8888
    # Create a listener which automatically exits after 4 established sessions
    listen --count 4 --platform windows 5555
