Tamper
======

``pwncat`` tracks modifications of the remote system through the ``tamper`` module. Programmatically, ``pwncat``
interfaces with the tamper subsystem through the ``pwncat.victim.tamper`` object. This allows generic modifications
to be registered with a method to revert the change. Built-in capabilities like ``privesc`` and ``persist`` will
any modifications made to the remote system with the tamper module. This includes but is not limited to created users,
created files, modified files, and removed files.

Listing Tampers
---------------

To view a list of current remote modifications, use the ``tamper`` command. The default action is to list all registered
tampers.

.. code-block:: bash

    (local) pwncat$ tamper
     0 - Created file /tmp/tmp.U2KlLIG5dW
     1 - Modified /home/george/.ssh/authorized_keys
     2 - Created file /tmp/tmp.tnJfd2BaCd
     3 - Created file /tmp/tmp.PAXFRgfYzW
     4 - Modified /home/george/.ssh/authorized_keys
     5 - Created file /tmp/tmp.xi5Evy4ZPF
     6 - Created file /tmp/tmp.05AwnolMNL
     7 - Modified /home/george/.ssh/authorized_keys
     8 - Created file /tmp/tmp.6LwcrXSdWE
     9 - Persistence: passwd as system (local)

Reverting Tampers
-----------------

Tampers can be reverted to their original state with the ``--revert/-r`` flag of the ``tamper`` command. In this mode,
can either specify ``--all/-a`` or ``--tamper/-t ID`` to revert all tampers or a specific tamper ID. In some cases, the
modifications were made as a different user and therefore cannot be removed currently. In this case, the tamper is left
in the list and can be reverted later once you have the required privileges:

.. code-block:: bash

    (local) pwncat$ tamper -r -a
    [\] reverting tamper: Modified /home/george/.ssh/authorized_keys
    [?] Modified /home/george/.ssh/authorized_keys: revert failed: No such file or directory: '/home/george/.ssh/authorized_keys'
    [/] reverting tamper: Created file /tmp/tmp.tnJfd2BaCd
    [?] Created file /tmp/tmp.tnJfd2BaCd: revert failed: /tmp/tmp.tnJfd2BaCd: unable to remove file
    [\] reverting tamper: Modified /home/george/.ssh/authorized_keys
    [?] Modified /home/george/.ssh/authorized_keys: revert failed: No such file or directory: '/home/george/.ssh/authorized_keys'
    [/] reverting tamper: Created file /tmp/tmp.xi5Evy4ZPF
    [?] Created file /tmp/tmp.xi5Evy4ZPF: revert failed: /tmp/tmp.xi5Evy4ZPF: unable to remove file
    [\] reverting tamper: Modified /home/george/.ssh/authorized_keys
    [?] Modified /home/george/.ssh/authorized_keys: revert failed: No such file or directory: '/home/george/.ssh/authorized_keys'
    [/] reverting tamper: Created file /tmp/tmp.6LwcrXSdWE
    [?] Created file /tmp/tmp.6LwcrXSdWE: revert failed: /tmp/tmp.6LwcrXSdWE: unable to remove file
    [-] reverting tamper: Persistence: passwd as system (local)
    [?] Persistence: passwd as system (local): revert failed: Permission denied: '/etc/passwd'
    [+] tampers reverted!

After utilizing our ``passwd`` persistence to gain root access, we can successfully remove all tampers:

.. code-block:: bash

    (local) pwncat$ privesc -e
    [+] privilege escalation succeeded using:
     ⮡ persistence - passwd as system (local)
    [+] pwncat is ready 🐈

    (remote) root@pwncat-centos-testing:~#
    [+] local terminal restored
    (local) pwncat$ tamper -r -a
    [+] tampers reverted!
    (local) pwncat$ tamper
    (local) pwncat$