Installation
============

.. toctree::
    :maxdepth: -1

The only system dependency for ``pwncat`` is ``python3`` and ``pip``. For ``pip`` to install all Python dependencies,
you will likely need your distributions Python Development package (``python3-dev`` for Debian-based distributions).
Once you have a working ``pip`` installation, you can install ``pwncat`` with the provided setup script:

.. code-block:: bash

    python setup.py --user install

It is recommended to use a virtual environment, however. This can be done easily with the Python3 ``venv`` module:

.. code-block:: bash

    python -m venv env
    source env/bin/activate
    python setup.py install

When updating ``pwncat`` is it recommended to setup and update the virtual environment again.

After installation, you can use ``pwncat`` via the installed script:

.. code-block:: bash

    $ pwncat --help
    usage: pwncat [-h] [--config CONFIG] [--identity IDENTITY] [--listen] [--port PORT]
                  [[protocol://][user[:password]@][host][:port]] [port]

        Connect to a remote victim. This command is only valid prior to an established
        connection. This command attempts to act similar to common tools such as netcat
        and ssh simultaneosly. Connection strings come in two forms. Firstly, pwncat
        can act like netcat. Using `connect [host] [port]` will connect to a bind shell,
        while `connect -l [port]` will listen for a reverse shell on the specified port.

        The second form is more explicit. A connection string can be used of the form
        `[protocol://][user[:password]@][host][:port]`. If a user is specified, the
        default protocol is `ssh`. If no user is specified, the default protocol is
        `connect` (connect to bind shell). If no host is specified or `host` is "0.0.0.0"
        then the `bind` protocol is used (listen for reverse shell). The currently available
        protocols are:

        - ssh
        - connect
        - bind

        The `--identity/-i` argument is ignored unless the `ssh` protocol is used.


    positional arguments:
      [protocol://][user[:password]@][host][:port]
                            Connection string describing the victim to connect to
      port                  Alternative port number argument supporting netcat-like syntax

    optional arguments:
      -h, --help            show this help message and exit
      --config CONFIG, -c CONFIG
                            Path to a configuration script to execute prior to connecting
      --identity IDENTITY, -i IDENTITY
                            The private key for authentication for SSH connections
      --listen, -l          Enable the `bind` protocol (supports netcat-like syntax)
      --port PORT, -p PORT  Alternative port number argument supporting netcat-like syntax

SSH Connection Errors
---------------------

Due to the way that SSH channels are abstracted, a custom fork of ``paramiko`` was required to fit into ``pwncat``.
I submitted a pull request with Paramiko, but it was never merged. Therefore, ``pwncat`` is currently utilizing a
custom fork of ``paramiko`` which provides an interface which is closer to a standard socket. ``pwncat`` is smart
enough to tell you this is the problem, but for documentation's sake, this command should fix your problems:

.. code-block:: bash

   # Ensure that the correct paramiko is installed
   pip install -U git+https://git+https://github.com/calebstewart/paramiko

If you installed ``pwncat`` within a virtual environment, this should obviously be done inside the virtual environment.
If you did not install within a virtual environment, this change may break other python tools which depend on a later
version of paramiko (however it should not affect things which depend on an equal version).

This problem is discussed `here <https://github.com/calebstewart/pwncat/issues/60>`_.

Development Environment
-----------------------

If you would like to develop modules for ``pwncat`` (such as privilege escalation or persistence module), you can use
the ``setuptools`` "develop" target instead of "install". This installs ``pwncat`` via symlinks, which means any
modifications of the local code will be reflected in the installed package:

.. code-block:: bash

    python setup.py develop

