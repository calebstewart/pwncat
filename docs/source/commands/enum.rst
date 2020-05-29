Enum
====

The ``enum`` command is used to enumerated facts on the victim host. These facts could be
system properties, installed packages, SUID binaries, various file permissions, etc. In
general, they are system properties which may be useful for privilege escalation.

``pwncat`` enumeration modules are based on a variety of Linux enumeration methodologies
and other fabulous enumeration scripts such as LinPEAS or LinEnum. ``pwncat`` takes these
methodologies and implements the enumeration in such a way that the raw information is
available to both the automated ``pwncat`` modules and to the user in a formatted and
readable way.

In this way, ``pwncat`` may automatically perform some enumeration while attempting to
escalate privieleges, but these enumerated facts will not be lost if the escalation
fails. For example, the ``privesc`` module always searches for SUID binaries. Even if a
path to the root user is not identified, ``pwncat`` utilizes the ``enumerate`` module
to track enumerated facts like SUID binaries. This speeds up future privilege escalation
as well as allows the user to give the enumerated data a human review.

Facts
-----

``pwncat`` uses the term "fact" to describe any individual piece of data which is
enumerated by the ``enumerate`` module. Each fact will have a type, a source and some
abstract data. All data must implement the ``__str__`` operator which is used for the
short form of the enumeration output. Further, data objects may implement a ``description``
property which contains a longer form description of the data suitable for more in-depth
inspection.

Different types of facts have different data types. If you request a "suid" fact type,
then each item is expected to have data objects of the class ``pwncat.enumerate.suid.Binary``
This generic interface allows the ``enum`` command to intelligently build reports while
not knowing the underlying data type. Further, if the underlying data type is known,
``pwncat`` can interact with the raw data (such as the SUID binaries path or owner UID).

Viewing Facts
-------------

The ``--show/-s`` argument to the ``enum`` command provides a way to view facts about
the victim host. If a specific fact type is requested, ``pwncat`` will first look for
facts of this type in the fact table of the database. Next, ``pwncat`` will check for
enumerator modules which provide the given type and run any which are available.

The default type of data is ``all``. This can take some time as ``pwncat`` has multiple
types of enumerator modules implemented. There is also a ``--quick`` option which will
only select a few useful and fast enumeration types which may be useful. Further, you
can pass the ``--type/-t`` parameter with the name of an enumeration type you would
like. Enumeration types are dynamic, but a known set of types at runtime can be found
by tab-completing the ``--type`` argument.

.. code-block:: bash
    :caption: Requesting quick enumeration facts

    $ pwncat -C data/pwncatrc -c -H 1.1.1.1 -p 4444
    [+] connection to 1.1.1.1:4444 established
    [+] setting terminal prompt
    [+] running in /bin/sh
    [+] terminal state synchronized
    [+] pwncat is ready 🐈

    (remote) bob@pwncat-centos-testing:/root$
    [+] local terminal restored
    (local) pwncat$ enum --show --quick
    SYSTEM.HOSTNAME Facts by pwncat.enumerate.system
      pwncat-centos-testing
    SYSTEM.ARCH Facts by pwncat.enumerate.system
      Running on a x86_64 processor
    SYSTEM.DISTRO Facts by pwncat.enumerate.system
      Running CentOS Linux 8 (Core) (centos), Version 8, Build ID None.
    SYSTEM.KERNEL.VERSION Facts by pwncat.enumerate.system
      Running Linux Kernel 4.18.0-147.3.1.el8_1.x86_64
    SYSTEM.NETWORK.HOSTS Facts by pwncat.enumerate.system
      127.0.0.1 -> ['pwncat-centos-testing', 'pwncat-centos-testing']
      ::1 -> ['pwncat-centos-testing', 'pwncat-centos-testing']
      10.0.0.5 -> ['internal_testing.company.com']
    SYSTEM.NETWORK Facts by pwncat.enumerate.system
      Interface lo w/ address 127.0.0.1/8
      Interface lo w/ address ::1/128
      Interface eth0 w/ address 134.122.23.33/20
      Interface eth0 w/ address 10.10.0.6/16
      Interface eth0 w/ address fe80::d877:e2ff:fe42:3169/64
    WRITABLE_PATH Facts by pwncat.enumerate.writable_path
      /home/bob/.local/bin
      /home/bob/bin
    (local) pwncat$

Generating a Host Report
------------------------

The ``enum`` command is capable of generating a human-readable report in the form of
a Markdown document. Specifying the ``--report/-r`` argument enables this mode. When
generating a report, you can select specific fact types. ``pwncat`` will enumerate
all information for the remote host and output a comprehensive organized markdown
report to the specified file.

.. code-block:: bash
    :caption: Generating the Report

    (local) pwncat$ enum --report ./report.md
    [+] enumeration report written to ./report.md
    (local) pwncat$