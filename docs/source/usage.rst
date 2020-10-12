Basic Usage
===========

``pwncat`` has two main modes which it operates in: Command Mode and Raw Mode. In command mode,
you are given a prompt with the ``(local)`` prefix. This prompt provides access to ``pwncat`` commands
for everything from file upload/download to automated privilege escalation. In command mode, you
control the remote host over the same communications channel, and therefore cancelling local commands
with "C-c" may leave your raw prompt in a precarious state.

The local prompt is governed by a command parser based on Python's ``prompt_toolkit`` module. It
will syntax highlight and tab-complete commands and arguments, and provides extensive help which
is auto-generated from the docstrings within the code itself.

In raw mode, ``pwncat`` disables echoing on your local terminal and places it in raw mode. Each
individual keystroke is forwarded to the remote terminal. This allows you to interact with the remote
terminal as if you were logged in locally or over SSH. Things like keyboard shortcuts, escape sequences
and graphical terminal applications will behave normally.

Transitioning between these two modes is accomplished internally by changing the ``pwncat.victim.state``
property. This property is a Python ``Enum`` object. From a user perspective, this state can be toggled
between Raw and Command mode with the "C-d" key sequence. The reason for selecting "C-d" is two-fold.
Firstly, "C-d" is a common way to exit a shell. Intercepting this control sequence prevents you from
habitually pressing this key combination and accidentally exiting your remote shell. Further, because
of it's common function, it feels natural to use this combination to switch between (or temporarily exit)
the different states.

You might be wondering "great, but how do I send a 'C-d' to the remote process!?" Well, ``pwncat``
allows this through the use of the defined prefix key. Similar to terminal applications like ``tmux``,
``pwncat`` has the concept of a "prefix" key. This key is pressed prior to entering a defined keyboard
shortcut to tell the input processor to interpret the next keystroke differently. In ``pwncat``, the
default prefix is "C-k". This means that to send the "C-d" sequence to the remote terminal, you can
press "C-k C-d" and to send "C-k" to the remote terminal, you can press "C-k C-k". Keyboard shortcuts
can be connected with any arbitrary script or local command and can be defined in the configuration file
or with the ``bind`` command.

Command Line Interface and Start-up Sequence
--------------------------------------------

The ``pwncat`` module installs a main script of the same name as an entry point to ``pwncat``. The
command line parameters to this command are the same as that of the ``connect`` command. During startup,
``pwncat`` will initialize an unconnected ``pwncat.victim`` object. It will then pass all arguments to
the entrypoint on to the ``connect`` command. This command is capable of loading and executing a
configuration script as well as connecting via various methods to a remote victim.

If a connection is not established during this initial connect command (for example, if the victim
cannot be contacted or the ``--help`` parameter was specified), ``pwncat`` will then exit. If a
connection *is* established, ``pwncat`` will enter the main Raw mode loop and provide you with
a shell.

C2 Channels
-----------

``pwncat`` allows the use of a few different C2 channels when connecting to a victim. Originally, ``pwncat``
wrapped a raw socket much like ``netcat`` with some extra features. As the framework was expanded, we have
moved toward abstracting this command and control layer away from the core ``pwncat`` features to allow
more ways of connection. Currently, only raw sockets and ``ssh`` are implemented. You can connect to a victim
with three different C2 protocols: ``bind``, ``connect``, and ``ssh``. The first two act like netcat. These
modes simply open a raw socket and assume there is a shell on the other end. In SSH mode, we legitimately
authenticate to the victim host with provided credentials and utilize the SSH shell channel as our C2 channel.

``pwncat`` exposes these different C2 channel protocols via the ``protocol`` field of the connection string
discussed below.

Connecting to a Victim
----------------------

Connecting to a victim is accomplished through a connection string. Connection strings are versatile ways
to describe the parameters to a specific C2 Channel/Protocol. This looks something like:
``[protocol://][user[:password]]@[host:][port]``

Each field in the connection string translates to a parameter passed to the C2 channel. Some channels don't
require all the parameters. For example, a ``bind`` or ``connect`` channel doesn't required a username or
a password.

If the ``protocol`` field is not specified, ``pwncat`` will attempt to figure out the correct protocol
contextually. The following rules apply:

- If only the host is provided, the protocol is assumed to be ``reconnect``
- If a user and host are provided:
  - If the ``--identity/-i`` parameter is not used, then ``reconnect`` is attempted.
  - If no matching persistence methods are available, ``ssh`` is assumed.
  - This allows simple reconnections while also supporting the ``ssh``-style syntax.
- If no user is provided but a host and port are provided, assume protocol is ``connect``
- If no user or host is provided (or host is ``0.0.0.0``), protocol is assumed to be ``bind``
- If a second positional integer parameter is specified, the protocol is assumed to be ``connect``
  - This is the ``netcat`` syntax seen in the below examples for the ``connect`` protocol.
- If the ``-l`` parameter is used, the protocol is assumed to be ``bind``.
  - This is the ``netcat`` syntax seen in the below examples for the ``bind`` protocol.

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

Connecting to a Remote SSH Server
---------------------------------

If you were able to obtain a valid password or private key for a remote user, you can initiate a ``pwncat``
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

Reconnecting to a victim
------------------------

If you previously had a ``pwncat`` session with a remote host and installed a persistence mechanism, you may
be able to leverage ``pwncat`` to automatically reconnect to the victim host utilizing your persistence
machanism. For this to work, you must specify a configuration file which provides a database for ``pwncat``
to use. With a configuration file specified, you can use the ``--list`` argument to list known hosts and
their associated persistence methods.

.. code-block:: bash
    :caption: Listing known host/persistence combinations

    pwncat -C data/pwncatrc --list
    192.168.1.1 - "centos" - 999c434fe6bd7383f1a6cc10f877644d
      - authorized_keys as root

Each host is identified by a host hash as seen above. You can reconnect to a host by either specifying a host
hash or an IP address. If multiple hosts share the same IP address, the first in the database will be selected
if you specify an IP address. Host hashes are unique across hosts.

Reconnecting is done through the ``reconnect`` protocol. If a user is not specified, the root is preferred. If
not persistence method for root is available, then the first available user is selected. The password field of
the connection string is used for the persistence module name you would like to use for reconnection. If no
password is specified, then all modules are tried and the first to work is used.

.. code-block:: bash
    :caption: Reconnecting to a known host

    # Assumed protocol
    pwncat 999c434fe6bd7383f1a6cc10f877644d
    pwncat user@192.168.1.1
    # Reconnect via a known host hash
    pwncat reconnect://999c434fe6bd7383f1a6cc10f877644d
    # Reconnect to first matching host with IP
    pwncat reconnect://192.168.1.1
    # Reconnect with specific user
    pwncat "reconnect://root@999c434fe6bd7383f1a6cc10f877644d"
    # Reconnect utilizing the authorized_keys persistence for user bob
    pwncat reconnect://bob:authorized_key@999c434fe6bd7383f1a6cc10f877644d

