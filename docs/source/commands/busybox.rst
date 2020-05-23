Busybox
=======

``pwncat`` works by try as much as possible not to depend on specific binaries on the remote system. It does this
most of the time by selecting an unidentified existing binary from the GTFOBins database in order to perform a
generic capability (e.g. file read, file write or shell). However, sometimes a critical binary is missing on the
target host which has been removed (either maliciously or never installed). In these situations, obtaining a stable
version of all basic binaries is very helpful. To this end, ``pwncat`` has the capability to automatically upload a
copy of the ``busybox`` program to the remote host.

The ``busybox`` command manages the installation, status, and removal of the installed busybox. Installing busybox lets
``pwncat`` know that it has a list of standard binaries with known good interfaces easily accessible. The ``busybox``
command also understands how to locate a ``busybox`` binary precompiled for the victim architecture and upload it
through the existing C2 channel. The new busybox installation will be installed in a temporary directory, and any
further automated tools within ``pwncat`` will use it's implementation of common unix tools.

Installation
------------

To install busybox on the remote victim, you can use the ``--install`` option to the ``busybox`` command. This will
first check for an existing, distribution specific, installation on the remote host. If the ``busybox`` command exists,
it will utilize that vice installing a new copy. If it doesn't, it will begin proxying a connection to the official
busybox servers to upload a busybox binary specific to the victim architecture.

After installation, ``pwncat`` will examine the endpoints provided by busybox, and remove any that are provided SUID by
the remote system. This prevents ``pwncat`` from replacing the real ``su`` binary with ``busybox su`` in it's database.

.. code-block::

    (local) pwncat$ busybox --install
    uploading busybox for x86_64
     100.0% [==================================================>] 1066640/1066640 eta [00:00]
    [+] uploaded busybox to /tmp/busyboxIu1gu
    [+] pruned 164 setuid entries
    (local) pwncat$

Status and Applet List
----------------------

To check if busybox has been installed and is known by ``pwncat`` (for example from a previous session), you can use the
``--status`` option. This is the default action, and can be accessed by passing no parameters to ``busybox``:

.. code-block:: bash

    (local) pwncat$ busybox
    [+] busybox is installed to: /tmp/busyboxIu1gu
    [+] busybox provides 232 applets
    (local) pwncat$

If you would like to see a list of binaries which busybox is currently providing for ``pwncat``, you can use the ``--list``
option. This is normally a large list (232 lines in this case), but it is provided for completeness sake.

.. code-block:: bash

    (local) pwncat$ busybox --list
    [+] binaries which the remote busybox provides:
     * [
     * [[
     * acpid
     * add-shell
     * addgroup
     * adduser
     * adjtimex
    ... removed for brevity ...

Removing Busybox
----------------

Busybox is tracked by ``pwncat`` as a remote tamper. This means that the ``tamper`` command will show that you have
installed busybox, and ``busybox`` can be uninstalled using the ``tamper`` command:

.. code-block::

    (local) pwncat$ tamper
     0 - installed busybox to /tmp/busyboxIu1gu
    (local) pwncat$ tamper -r -t 0
    (local) pwncat$ busybox --status
    [!] busybox hasn't been installed yet
    (local) pwncat$
