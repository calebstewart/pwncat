Installation
============

.. toctree::
    :maxdepth: -1

The only system dependency for pwncat is ``python3`` and ``pip``. For ``pip`` to install all Python dependencies, you will likely need your distributions Python Development package (``python3-dev`` for Debian-based distributions). A virtual environment is recommended, but not required.

.. code-block:: bash
    :caption: Install pwncat w/ Virtual Environment

    # A virtual environment is recommended
    python -m venv /opt/pwncat
    # Install pwncat within the virtual environment
    /opt/pwncat/bin/pip install pwncat-cs
    # This allows you to use pwncat outside of the virtual environment
    ln -s /opt/pwncat/bin/pwncat /usr/local/bin

.. code-block:: bash
    :caption: Install pwncat without Virtual Environment

    pip install pwncat-cs

After installation, you can use pwncat via the installed script:

.. code-block:: bash

    $ pwncat-cs --help
    usage: pwncat-cs [-h] [--version] [--download-plugins] [--config CONFIG] [--ssl] [--ssl-cert SSL_CERT]
                     [--ssl-key SSL_KEY] [--identity IDENTITY] [--listen] [--platform PLATFORM] [--port PORT] [--list]
                     [[protocol://][user[:password]@][host][:port]] [port]

    Start interactive pwncat session and optionally connect to existing victim via a known platform and channel type. This
    entrypoint can also be used to list known implants on previous targets.

    positional arguments:
      [protocol://][user[:password]@][host][:port]
                            Connection string describing victim
      port                  Alternative port number to support netcat-style syntax

    optional arguments:
      -h, --help            show this help message and exit
      --version, -v         Show version number and exit
      --download-plugins    Pre-download all Windows builtin plugins and exit immediately
      --config CONFIG, -c CONFIG
                            Custom configuration file (default: ./pwncatrc)
      --ssl                 Connect or listen with SSL
      --ssl-cert SSL_CERT   Certificate for SSL-encrypted listeners (PEM)
      --ssl-key SSL_KEY     Key for SSL-encrypted listeners (PEM)
      --identity IDENTITY, -i IDENTITY
                            Private key for SSH authentication
      --listen, -l          Enable the `bind` protocol (supports netcat-style syntax)
      --platform PLATFORM, -m PLATFORM
                            Name of the platform to use (default: linux)
      --port PORT, -p PORT  Alternative way to specify port to support netcat-style syntax
      --list                List installed implants with remote connection capability

BlackArch Package
-----------------

pwncat is packaged for BlackArch and in the standard repositories. Installation on
BlackArch is as simple as:

.. code-block:: bash

    $ pacman -Syu pwncat-caleb

Windows Plugin Binaries
-----------------------

The Windows target utilizes .Net binaries to stabilize the connection and bypass
various defenses present on Windows targets. The base Windows C2 utilizes two DLLs
named ``stageone.dll`` and ``stagetwo.dll``. Stage One is a simple reflective loader.
It will read the encoded and compressed contents of Stage Two, and execute it
reflectively. Stage Two contains the actual meat of the C2 framework.

Further, the Stage Two C2 framework provides the ability to reflectively load other
.Net assemblies and execute their methods. The loaded assemblies must conform to the
pwncat plugin API. These APIs are not generally accessible from the interactive
session, and are created more for the Python API.

Plugins are stored at the path specified by the ``plugin_path`` configuration value.
By default, this configuration points to ``~/.local/share/pwncat``, but can be changed
by your configuration file. If a plugin does not exist when it is requested, the appropriate
version will be downloaded via a URL tracked within pwncat itself.

If your attacking machine will not have direct internet access, you can prestage the
plugin binaries in two ways. The easiest is to connect your attacking machine to
the internet, and use the ``--download-plugins`` argument:

.. code-block:: bash

    pwncat --download-plugins

This command will place all built-in plugins in the plugin directory for you. Alternatively,
if you are using a release version pwncat, you can download a prepackaged tarball of all
builtin plugins from the GitHub releases page. You can then extract it into your plugin path:

.. code-block:: bash

    # Replace {version} with your pwncat version
    cd ~/.local/share/pwncat
    wget https://github.com/calebstewart/pwncat/releases/download/{version}/pwncat-plugins-{version}.tar.gz
    tar xvfs pwncat-plugins-{version}.tar.gz
    rm pwncat-plugins-{version}.tar.gz


Development Environment
-----------------------

pwncat utilizes the Poetry dependency and build manager. After installing poetry, you can use it to manage a local development environment.

.. code-block:: bash

    git clone https://github.com/calebstewart/pwncat.git
    cd pwncat
    poetry shell
    poetry install
