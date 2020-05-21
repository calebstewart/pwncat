Configuration
=============

.. toctree::
    :maxdepth: -1

pwncat is configured using a script written in the same language as the local
prompt. The script is specified with the ``--config/-c`` parameter of the pwncat
command. All commands from the local prompt are available in the configuration
file. Commands which interact with the remote host are restricted until a
stable remote connection is established. Specifically, the following commands
are allowed at any scope in the configuration file:

- set
- bind
- alias
- shortcut

Configuration Parameters
------------------------

To run commands and interact with the remote host upon successful connection,
you can specify a script to run via the ``set`` command:

.. code-block:: bash

    set on_load {
        persist --install --method authorized_keys
    }

Besides the on-load script, the following configuration values can be set:

* lhost - your attacking ip from the perspective of the victim
* prefix - the key used as a prefix for keyboard shortcuts
* privkey - the private key used for RSA-based persistence
* backdoor_user - the username to insert for backdoor persistence
* backdoor_pass - the password for the backdoor user
* db - a SQLAlchemy connection string for the database to use
* on_load - a script to run upon successful connection

User Credentials
----------------

The ``set`` command can also be used to specify user credentials. When used in this
form, it can only be used after client connection. To specify a user password,
you can use the "--password/-p" parameter:

.. code-block:: bash

    set -p bob "b0b5_P@ssw0rd"

Key Bindings
------------

Key bindings are keys which trigger specific commands or scripts to run after
being pressed. To access key bindings, you must first press your defined prefix.
By default, one binding is enabled, which is ``s``. This will synchronize the
terminal state with your local terminal, which is helpful if you change the
width and height of your terminal window. A key binding can either be a single
command specified in quotes, or a script block specified in braces as with the
``on_load`` callback. Examples of key bindings:

.. code-block:: bash

    # Enter the local prompt for a single command, then return to raw terminal
    # mode
    bind c "set state single"
    # Enumerate privilege escalation methods
    bind p "privesc -l"

Aliases
-------

Basic command aliases can be defined using the ``alias`` command. Aliases can
only be to base commands, and cannot contain scripts or command parameters.
Examples of basic aliases:

.. code-block:: bash
    
    alias up upload
    alias down download

Shortcuts
---------

Shortcuts provide single-character prefixes to act as commands. The entire
command string after the prefix is sent as the parameters to the specified
command. The following two shortcuts are provided to enable running local and
remote shell commands from the pwncat prompt:

.. code-block:: bash

    shortcut ! local
    shortcut @ run


