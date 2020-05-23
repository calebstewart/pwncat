Bruteforce
----------

The ``bruteforce`` command is used to bruteforce authentication of a user locally. It will use the ``su`` command to
iteratively try every password for a given user. This is very slow, but does technically work. If no wordlist is
specified, the default location of ``rockyou.txt`` in Kali Linux is chosen. This may or may not exist for your system.

.. warning::
    This command is very noisy in log files. Each failed authentication is normally logged by any modern
    linux distribution. Further, if account lockout is enabled, this will almost certainly lockout the
    targeted account!

Selecting a User
----------------

Individual users are selected with the ``--user`` argument. This argument can be passed multiple times to test multiple
users in one go. To use the default dictionary to test the root and bob users, you would issue a command like:

.. code-block:: bash

    bruteforce -u root -u bob

User names are automatically tab-completed at the ``pwncat`` prompt for your victim host.

Selecting a Wordlist
--------------------

Word lists are specified with the ``--dictionary`` parameter. This parameter is a path to a file on your attacking
host which contains a list of passwords to attempt for the selected users. If a correct password is found, it is stored
in the databaase, and the search is aborted for that user. To select a custom database, you would issue a command like:

.. code-block:: bash

    bruteforce -d /opt/my-favorite-repo/my-favorite-wordlist.txt -u root

