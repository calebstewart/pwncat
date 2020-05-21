Interacting With The Victim
===========================

pwncat abstracts all interactions with the remote host through the ``pwncat.victim`` object. This is
a singleton of the ``pwncat.remote.Victim`` class, and is available anywhere after initialization and
conneciton of the remote host.

This object wraps common operations on the remote host such as running processes, retrieving output,
opening files, interacting with services and much more!

Working with remote processes
-----------------------------

Remote processes are started with one of four different methods. However, most of the time you will
only need to use two of them. The first is the ``process`` method:

.. code-block:: python

    start_delim, end_delim = pwncat.victim.process("ls", delim=False)

The ``process`` method does not attempt to handle the output of a process or verify it's success.
The ``delim`` parameter specifies whether delimeters will be placed before and after the remote
processes output. If ``delim`` is false, this is equivalent to sending the command over the socket
directly with ``pwncat.victim.client.send("ls\n".encode("utf-8"))``. However, setting ``delim`` to
True (the default value) instructs the method to prepend and append delimeters. ``process`` will
also wait for the starting delimeter to be sent before returning. This means that with ``delim``
on, reading data from ``pwncat.victim.client`` after calling process with be the output of the process
up until the end delimeter.

The next process creation method is ``run``. This method utilizes ``process``, but automatically waits
for process completion and returns the output of the process:

.. code-block:: python

    output: bytes = pwncat.victim.run("ls")

The optional ``wait`` parameter effects whether the method will wait for and return the result. If
``wait`` is false, the output will not be read from the socket and the method will return immediately.
This behaves much like calling ``process`` with ``delim=True``.

The third process creation method is ``subprocess``. With the subprocess method, a file-like object
is returned which allows for read/write access to the remote processes stdio. Writing to the remote
process will work until the end delimeter is observed on a read. Afterwich, the file object is
automatically closed. No other interaction with the remote host is possible until the file object
is closed.

.. code-block:: python

    with pwncat.victim.subprocess("find / -name 'interesting'", "r") as pipe:
        for line in pipe:
            print("Interesting file:", line.strip().decode("utf-8"))

The last process creation method is the ``env`` method. This method acts much like the ``env`` command
on linux. It takes an argument array for a process to start. The first argument is the name of the
program to run, and it is check with the ``pwncat.victim.which`` method to ensure it exists. Keyword
arguments to the method are converted into environment variables for the new process. A ``FileNotFoundError``
is raised if the requested binary is not resolved properly with ``pwncat.victim.which``.

.. code-block:: python

    pwncat.victim.env(["mkdir", "-p", "/tmp/somedir"], ENVIRONMENT_VAR="variable value")

This method also takes parameters similar to ``run`` for waiting and input, if needed.

Working with remote files
-------------------------

Remote files can be accessed and created similar to local files. The ``pwncat.victim.open`` interface
provides a method to open a remote file and interact with it like a local Python file object. Creating
a remote file can be accomplished with:

.. code-block:: python

    with pwncat.victim.open("/tmp/remote-file", "w") as filp:
        filp.write("hell from the other side!")

When interacting with remote files, no other interaction with the remote host is allowed. Prior to
executing any other remote interaction, you must close the remote file object. Because of this simple
interface, uploading a local file to a remote file can be accomplished with Python built-in functions.

.. code-block:: python

    import os
    import shutil

    with open("loca-file", "rb") as src:
        with pwncat.victim.open("/tmp/remote-file", "wb",
                length=os.path.getsize("local-file")) as dst:
            shutil.copyfileobj(src, dst)

This is actually how the ``upload`` and ``download`` commands are implemented. The ``length`` parameter
to the ``pwncat.victim.open`` method allows ``pwncat`` to intelligently select remote file access options
which required a length argument. This is important because transfer of raw binary data unencoded requires
the output length to be known. If the length is not passed, the data will be automatically encoded (for
example, with base64) before uploading, and decoded automatically on the receiving end.

Working with remote services
----------------------------

``pwncat`` will attempt to figure out what type of init system is being used on the target host and provide
an abstracted interface to system services. The abstractions are available under the ``pwncat/remote/service.py`` file.
Currently, ``pwncat`` only supports SystemD, but the interface is abstracted to support other init systems
such as SysVInit or Upstart if the interface is implemented.

The ``pwncat.remote.service.service_map`` maps names of init systems to their abstract ``RemoteService``
class implementation. This is how ``pwncat`` selects the appropriate remote service backend.

Regardless of the underlying init system, ``pwncat`` provides methods for querying known services, enabling
auto-start, starting, stopping and creation of remote services.

To query a list of remote services, you can use the ``pwncat.victim.services`` property. This is an iterator
yielding each abstracted service object. Each object contains a name, description, and state as well as
methods for starting, stopping, enabling or disabling the service. This functionality obviously depends
on you having the correct permission to manage the services, however retrieve the state and list of
services should work regardless of your permission level.

.. code-block:: python

    from pwncat import victim

    for service in victim.services:
        print(f"{service.name} is {'running' if service.running else 'stopped'}")

To find a specific service by name, there is a ``find_service`` method which returns an individual
remote service object. If the service is not found, a ValueError is raised.

.. code-block:: python

    from pwncat import victim

    sshd = victim.find_service("sshd")


The interface for creating services is provided through the ``create_service`` method, which allows
you to specify a target binary name which serves as the entrypoint for your service as well as a name
description, and enabled state. A ``PermissionError`` is raised if you do not have permission to create
the specified service. This method also returns a wrapped ``RemoteService`` object for the newly
created service.

.. code-block:: python

    from pwncat import victim

    pwncat = victim.create_service(name="pwncat",
                                   description="a malicious service",
                                   target="/usr/bin/pwncat_service",
                                   runas="root",
                                   enable=True,
                                   user=False)
    pwncat.start()

Starting, stopping or enabling a service is as easy as calling a method or setting a property:

.. code-block:: python

    from pwncat import victim

    try:
        sshd = victim.find_service("sshd")
        sshd.enabled = False
        sshd.stop()
    except PermissionError:
        print("you don't have permission to modify sshd :(")
    except ValueError:
        print("sshd doesn't exist!")

The Victim Object
-----------------

.. autoclass:: pwncat.remote.victim.Victim
    :members:

Remote Service Object
---------------------

.. autoclass:: pwncat.remote.service.RemoteService
    :members:
