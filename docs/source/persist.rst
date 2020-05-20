Persistence
===========

The ``pwncat.victim.persist`` module provides an abstract way to install various persistence methods
on the target host. To view a list of available persistence methods, you can use the ``--list/-l``
switch:

.. code-block:: bash

    (local) pwncat$ persist -l
     - authorized_keys as user (local)
     - pam as system (local)
     - passwd as system (local)
     - sshd as system (local)

This output indicates a few things. First, if a given method specifies "as user", then the persistence
method is installed as a specific user. If no user is specified during installation, ``root`` is
attempted, but will likely only succeed if you do not currently have root permissions. Second,
persistence methods marked "local" allow a local user to escalate to that user (or to root for system
persistence modules). This is in contrast to persistence methods which only allow remote access
as the specified user.

To get more information on a specific module, you can pass the ``--method/-m`` option with the method
name when using ``--list/-l``. This will provide the module specific documentation on what is being
installed specifically on the remote system:

.. code-block:: bash

    (local) pwncat$ persist -l -m pam
    pam as system (local)

      Add a malicious PAM module which will allow authentication as any user.
      This persistence method will install a custom PAM module which authenticates
      every user successfully with your backdoor password. This module also logs
      any passwords in plaintext which are not your backdoor password in /var/log/firstlog.
      The log file is tracked as a separate tamper and will not be automatically removed
      by removing this persistence method.

      The remote host **must** have `gcc` and `openssl-devel` packages installed
      and you must already have root access.

Persistence Installation Status
-------------------------------

To list all currently installed persistence methods, you can use the ``--status/-s`` switch. This
will list all registered/installed persistence methods known to ``pwncat``. This is also the default
action if no options are specified.

.. code-block:: bash

    (local) pwncat$ persist -s
     - pam as system (local) installed

This is useful because in some situations, the ``pwncat.victim.privesc`` module will automatically
install persistence. This is normally to overcome a ``EUID != UID`` situation. If this happens,
``pwncat`` will still track persistence methods correctly.

Persistence methods are also tracked by the ``pwncat.victim.tamper`` module. When a persistence
method is installed, it is registered as both a tamper and a persistence method. In this way, using
``tamper -r -a`` will remove all of your modifications including persistence methods. If a persistence
method is removed with tamper, it will also be removed from the persistence status and vice-versa.

Installing Persistence
----------------------

The ``persist`` command can be used to install individual persistence methods. The ``--install/-i``
switch enables this mode. In installation mode, you must specify a module to install with the
``--method/-m`` option. For user-based methods, you should also specify a user. If no user is specified,
``pwncat`` will assume you would like root-level persistence. For system methods, the user argument
is ignored.

.. code-block:: bash

    (local) pwncat$ persist -i -m pam
    [/] pam_sneaky: adding pam auth configuration: login
    (local) pwncat$ persist -i -m authorized_keys -u george
    (local) pwncat$ persist
     - pam as system (local) installed
     - authorized_keys as george (local) installed

Removing Persistence
--------------------

Once again, the ``persist`` command is used to remove persistence from the target host. The
``--remove/-r`` switch is used to enable this mode. You must specify a method with the ``--method/-m``
option. For user-based methods, you must specify a user to remove the persistence from. As with
the install, ``pwncat`` will assume you would like to remove the root persistence. If no user is
specified and persistence as root is not installed, the removal will fail.

.. code-block:: bash

    (local) pwncat$ persist -r -m authorized_keys -u george
    (local) pwncat$ persist -r -m authorized_keys
    [!] authorized_keys as root (local): not installed

As mentioned above, persistence installation is also tracked by the tamper command. The ``tamper``
command can also be used to view and remove persistence methods:

.. code-block:: bash

    (local) pwncat$ tamper
     0 - Created file /var/log/firstlog
     1 - Persistence: pam as system (local)
    (local) pwncat$ tamper -r -t 1



