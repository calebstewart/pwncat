Installation
============

.. toctree::
    :maxdepth: -1

The only system dependency for ``pwncat`` is ``python3`` and ``pip``. For ``pip`` to install all Python dependencies,
you will likely need your distributions Python Development package (``python3-dev`` for Debian-based distributions).
Once you have a working ``pip`` installation, you can install ``pwncat`` with the provided setup script:

.. code-block:: bash

    # A virtual environment is recommended
    python -m venv /opt/pwncat
    # Install pwncat within the virtual environment
    /opt/pwncat/bin/pip install git+https://github.com/calebstewart/pwncat
    # This allows you to use pwncat outside of the virtual environment
    ln -s /opt/pwncat/bin/pwncat /usr/local/bind

After installation, you can use ``pwncat`` via the installed script:

.. code-block:: bash

    $ pwncat --help
    usage: pwncat [-h] [--config CONFIG] [--identity IDENTITY] [--listen]
                  [--platform PLATFORM] [--port PORT] [--list]
                  [[protocol://][user[:password]@][host][:port]] [port]

    Start interactive pwncat session and optionally connect to existing victim
    via a known platform and channel type. This entrypoint can also be used to
    list known implants on previous targets.

    positional arguments:
      [protocol://][user[:password]@][host][:port]
                            Connection string describing victim
      port                  Alternative port number to support netcat-style
                            syntax

    optional arguments:
      -h, --help            show this help message and exit
      --config CONFIG, -c CONFIG
                            Custom configuration file (default: ./pwncatrc)
      --identity IDENTITY, -i IDENTITY
                            Private key for SSH authentication
      --listen, -l          Enable the `bind` protocol (supports netcat-style
                            syntax)
      --platform PLATFORM, -m PLATFORM
                            Name of the platform to use (default: linux)
      --port PORT, -p PORT  Alternative way to specify port to support netcat-
                            style syntax
      --list                List installed implants with remote connection
                            capability

Development Environment
-----------------------

If you would like to develop modules for ``pwncat`` (such as privilege escalation or persistence module), you can use
the ``setuptools`` "develop" target instead of "install". This installs ``pwncat`` via symlinks, which means any
modifications of the local code will be reflected in the installed package:

.. code-block:: bash

    git clone https://github.com/calebstewart/pwncat.git
    cd pwncat
    python -m venv env
    . env/bin/activate
    python setup.py develop

