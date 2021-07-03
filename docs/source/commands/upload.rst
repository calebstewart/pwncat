Upload
======

``pwncat`` makes file upload easy through the ``upload`` command. File upload is accomplished via
the ``gtfobins`` modules, which will enumerate available local binaries capable of writing printable
or binary data to files on the remote host. Often, this is ``dd`` if available but could be any
of the many binaries which ``gtfobins`` understands. The upload takes place over the same
connection as your shell, which means you don't need another HTTP or socket server or extra connectivity
to your target host.

At the local ``pwncat`` prompt, local and remote files are tab-completed to provided an easier upload
interface, and a progress bar is displayed.

.. code-block:: bash
    :caption: Upload a script to the remote host

    upload ./malicious.sh /tmp/definitely-not-malicious
