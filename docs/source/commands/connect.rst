Connect
=======

This command initiates or receives a connection to a remote victim and establishes
a pwncat session. Sessions can be established over any socket-like communication
layer. Currently, communications channels for reverse and bind shells over raw
sockets and SSH are implemented.

The connect command is written to take a flexible syntax. At it's core, it accepts
a connection string which looks like this: ``protocol://user:password@host:port``.
It also makes some assumptions if some or all of this connection string is missing.

The following assumptions are made if one or more of the above sections are missing

* If no protocol is specified, but the user and host are specified, assume SSH
  protocol.
* If no protocol, user, or port are specified, assume reconnect protocol.
* If no protocol, user, password or port are specified, assume reconnect protocol.
* If no protocol, user or password are specified and host is not 0.0.0.0, assume
  connect protocol.
* If no protocol, user, password or host are specified, assume bind protocol.

Further, any input which supplies a username (and optionally a password field) and
a host with no port or protocol will attempt to reconnect via installed persistence
first.

This command also accepts a second positional parameter to specify the port. This
parameter cannot be used along with the port within the connection string. The
reason for the second port argument is to support ``netcat`` like syntax.

These rules mean that you can invoke pwncat in a similar fashion to common
tools such as ``ssh`` and ``netcat``. For example, all of the following are valid:

.. code-block:: bash

   # Connect to a bind shell on 4444
   connect 10.10.10.10 4444
   connect connect://10.10.10.10:4444
   connect 10.10.10.10:4444
   # Listen for reverse shell on 4444
   connect bind://0.0.0.0:4444
   connect 0.0.0.0:4444
   connect :4444
   connect -lp 4444
   # Connect via ssh
   connect user@10.10.10.10
   connect -i id_rsa user@10.10.10.10
   connect user:password@10.10.10.10
   # Reconnect to host via IP, hostname or host hash
   connect user@[hostname, host hash or IP]
   connect reconnect://user:module@10.10.10.10
   connect [hostname, host hash or IP]

For more concrete examples, see the ``Basic Usage`` page. The arguments to pwncat are
the same as the arguments to ``connect``
