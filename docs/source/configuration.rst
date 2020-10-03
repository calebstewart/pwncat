Configuration
=============

.. toctree::
    :maxdepth: -1

``pwncat`` can load a configuration script from a few different locations.
First, if a file named ``pwncatrc`` exists in ``$XDG_CONFIG_HOME/pwncat/``
then it will be executed prior to any other configuration. Next, if no
``--config/-c`` argument is provided, and a file in the current directory
named ``pwncatrc`` exists, it will be executed. Lastly, if the
``--config/-c`` argument is specified, ``pwncat`` will load and run the
specified configuration script prior to establishing a connection.

The value of ``XDG_CONFIG_HOME`` depends on your environment but commonly
defaults to ``~/.config``. The purpose of this configuration script is for
global settings that you would like to persist across all instances of
``pwncat``.

The purpose of the explicit script (or implicit script in the current directory)
is for you to specify settings which are specific to this connection or
context. For example, you may have a different ``pwncatrc`` that specifies
a specific database location in your analysis directory while a configuration
exists in ``$XDG_CONFIG_HOME`` which loads custom modules. The database is
specific to a single machine or network while the global configuration may
apply to multiple machines, networks or engagements.

The syntax of the ``pwncatrc`` script is the same as the local prompt within
``pwncat``. This means you can generally use most commands that are available
there with the exception of any command which requires a connection be established.
For example, you cannot run enumeration or escalation modules (with the exception
of on_load scripts). You can, however, set key bindings, load module classes,
and set default configuration parameters.

Configuration Parameters
------------------------

Configuration parameters are modified with the ``set`` command. By default,
parameters are modified in the local context. This is meaningless if you are
not in a module context. Therefore, if you are setting global runtime parameters,
you should use the ``--global/-g`` flag.

To run commands and interact with the remote host upon successful connection,
you can specify a script to run via the ``set`` command:

.. code-block:: bash

    set -g on_load {
        persist --install --method authorized_keys
    }

The script between the braces will be run as soon as a victim is connected and
stable. Any command you can normally run from within ``pwncat`` is available.

Besides the on-load script, the following global configuration values can be set:

* lhost - your attacking ip from the perspective of the victim
* prefix - the key used as a prefix for keyboard shortcuts
* privkey - the private key used for RSA-based persistence
* backdoor_user - the username to insert for backdoor persistence
* backdoor_pass - the password for the backdoor user
* db - a SQLAlchemy connection string for the database to use
* on_load - a script to run upon successful connection

The ``set`` command is also used to set module arguments when with a module context.
In this case, the ``--global/-g`` flag is not used, and the values are lost upon
exiting the module context.

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


