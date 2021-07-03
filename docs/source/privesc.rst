Automated Privilege Escalation
==============================

``pwncat`` has the ability to attempt automated privilege escalation methods. A number of methods are implemented by
default such as:

* Set UID Binaries
* Sudo (with and without password)
* screen (CVE-2017-5618)
* DirtyCOW

Each of these methods utilize the capabilities of the GTFOBins module. The GTFOBins module provides a programmatic
interface to gtfobins_. Each privilege escalation module implements shell, file read or file write capabilities.
``pwncat`` will leverage these to get shell access as the specified user. ``pwncat`` does this by trying the following
methods with the provided capabilities:

* Executing a shell (the simplest option)
* Reading user private keys and ssh-ing to localhost
* Writing private keys
* Implanting a backdoor user in /etc/passwd (if file-write as root is available)

If ``pwncat`` does not find a method of gaining access as the specified user directly, it will attempt to escalate to
any other user it can recursively to attempt to find a path to the requested user.

Invoking Privilege Escalation
-----------------------------

Privilege escalation is implemented utilizing ``pwncat`` modules. These modules can be run individually
if desired or you can utilize the ``escalate.auto`` module which will recursively search for a path
to a desired user.

The ``escalate.auto`` module by default simply lists the escalation techniques which were found for the
current user. To actually escalate to a new user, you can use the ``exec`` option. This option will
go through every possible user and attempt to escalate. It then keeps attempting escalation until it finds
a path to the requested user recursively.

Escalation modules also implement ``read`` and ``write`` modes which attempt to read or write a file
as the specified user. All three of ``read``, ``write``, and ``exec`` are also supported by every
individual escalation module.

.. code-block:: bash

   # Locate and list available techniques as the current user
   (local) pwncat$ run escalate.auto
   # Attempt automated escalation to the specified user
   (local) pwncat$ run escalate.auto exec user=root shell=/bin/bash
   # Attempt automated escalation to root with the current shell
   (local) pwncat$ run escalate.auto exec
   # Read /etc/shadow with the escalate.sudo module
   (local) pwncat$ run escalate.sudo read user=root path=/etc/shadow
   # Write a file as root
   (local) pwncat$ run escalate.auto write user=root path=/tmp/test data="hello world!"


.. _gtfobins: https://gtfobins.github.io
