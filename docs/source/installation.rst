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
    pip install -r requirements.txt
    python setup.py install

When updating ``pwncat`` is it recommended to setup and update the virtual environment again.

After installation, you can use ``pwncat`` via the installed script:

.. code-block:: bash

    $ pwncat --help
    usage: pwncat [-h] (--reverse | --bind) [--host HOST] --port PORT
                  [--method {script-util-linux,script-other,python}] [--config CONFIG]

    optional arguments:
      -h, --help            show this help message and exit
      --reverse, -r         Listen on the specified port for connections from a remote host
      --bind, -b            Connect to a remote host
      --host HOST, -H HOST  Bind address for reverse connections. Remote host for bind connections (default:
                            0.0.0.0)
      --port PORT, -p PORT  Bind port for reverse connections. Remote port for bind connections
      --method {script-util-linux,script-other,python}, -m {script-util-linux,script-other,python}
                            Method to create a pty on the remote host (default: script)
      --config CONFIG, -c CONFIG
                            Configuration script

Development Environment
-----------------------

If you would like to develop modules for ``pwncat`` (such as privilege escalation or persistence module), you can use
the ``setuptools`` "develop" target instead of "install". This installs ``pwncat`` via symlinks, which means any
modifications of the local code will be reflected in the installed package:

.. code-block:: bash

    python setup.py develop

