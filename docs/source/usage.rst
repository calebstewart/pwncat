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
a shell. At the time of writing, the available ``pwncat`` arguments are:

.. code-block::
    :caption: pwncat argument help

    usage: pwncat [-h] [--exit] [--config CONFIG] [--listen] [--connect] [--ssh]
                  [--reconnect] [--list] [--host HOST] [--port PORT] [--method METHOD]
                  [--user USER] [--password PASSWORD] [--identity IDENTITY]

    Connect to a remote host via SSH, bind/reverse shells or previous persistence methods
    installed during past sessions.

    optional arguments:
      -h, --help            show this help message and exit
      --exit                Exit if not connection is made
      --config CONFIG, -C CONFIG
                            Path to a configuration script to execute prior to connecting
      --listen, -l          Listen for an incoming reverse shell
      --connect, -c         Connect to a remote bind shell
      --ssh, -s             Connect to a remote ssh server
      --reconnect, -r       Reconnect to the given host via a persistence method
      --list                List remote hosts with persistence methods installed
      --host HOST, -H HOST  Address to listen on or remote host to connect to. For
                            reconnections, this can be a host hash
      --port PORT, -p PORT  The port to listen on or connect to
      --method METHOD, -m METHOD
                            The method to user for reconnection
      --user USER, -u USER  The user to reconnect as; if this is a system method, this
                            parameter is ignored.
      --password PASSWORD, -P PASSWORD
                            The password for the specified user for SSH connections
      --identity IDENTITY, -i IDENTITY
                            The private key for authentication for SSH connections


Connection Methods
------------------

``pwncat`` is able to connect to a remote host in a few different ways. At it's core, ``pwncat`` communicates
with a remote shell over a raw socket. This can be either a bind shell or a reverse shell from a remote victim
host. ``pwncat`` also offerst the ability to connect to a remote victim over SSH with a known password or
private key. When connecting via SSH, ``pwncat`` provides the same interface and capabilities as with a
raw bind or reverse shell.

The last connection method relies on a previous ``pwncat`` session with the victim. If you install a persistence
method which support remote reconnection, ``pwncat`` can utilize this to initiate a new remote shell with the victim
automatically. For example, if you installed authorized keys for a specific user, ``pwncat`` can utilize these to
initiate another SSH session using your persistence. This allows you to easily reconnect in the event of a previous
session being disconnected.

Fully documentation on the methods and options for these connection methods can be found in the ``connect``
documentation under the Command Index. A few examples of connections can be found below.

Connecting to a victim bind shell
---------------------------------

In this case, the victim is running a raw bind shell on an open port. The victim must be available at an
address which is routable (e.g. not NAT'd). The ``--connect/-c`` mode provides this capability.

.. code-block:: bash
    :caption: Connecting to a bind shell at 1.1.1.1:4444

    pwncat --connect -H 1.1.1.1 -p 4444

Catching a victim reverse shell
-------------------------------

In this case, the victim was exploited in such a way that they open a connection to your attacking host
on a specific port with a raw shell open on the other end. Your attacking host must be routable from the
victim machine. This mode is accessed via the ``--listen/-l`` option for connect.

.. code-block:: bash
    :caption: Catching a reverse shell

    pwncat --listen -p 4444

Connecting to a Remote SSH Server
---------------------------------

If you were able to obtain a valid password or private key for a remote user, you can initiate a ``pwncat``
session with the remote host over SSH. This mode is accessed via the ``--ssh/-s`` option for connect.

.. code-block:: bash
    :caption: Connection to a remote SSH server w/ Password Auth

    pwncat -s -H 1.1.1.1 -u root -p "r00t5P@ssw0rd"

.. code-block:: bash
    :caption: Connection to a remote SSH server w/ Public Key Auth

    pwncat -s -H 1.1.1.1 -u root -i ./root-private-key

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
    1.1.1.1 - "centos" - 999c434fe6bd7383f1a6cc10f877644d
      - authorized_keys as root

Each host is identified by a host hash as seen above. You can reconnect to a host by either specifying a host
hash or an IP address. If multiple hosts share the same IP address, the first in the database will be selected
if you specify an IP address. Host hashes are unique across hosts.

.. code-block:: bash
    :caption: Reconnecting to a known host

    # Reconnect w/ host hash
    pwncat -C data/pwncatrc --reconnect -H 999c434fe6bd7383f1a6cc10f877644d
    # Reconnect to first host w/ matching IP
    pwncat -C data/pwncatrc --reconnect -H 1.1.1.1

Other options are available to specify methods or users to reconnect with. These options are covered in more detail
in the ``connect`` documentation under the Command Index.

