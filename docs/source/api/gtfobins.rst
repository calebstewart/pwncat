GTFOBins Abstraction Layer
==========================

``pwncat`` implements an abstraction of the fantastic GTFOBins_ project. This project catalogs
known methods of file read, file write and shell access with commonly accessible binaries.

The ``pwncat.gtfobins`` module along with the ``data/gtfobins.json`` database provides a
programmatic way of enumerating and searching for known GTFObins techniques for performing
various capabilities. It is able to generate payloads for gaining a shell, file read, and
file write in standard, SUID or sudo modes.

For the standard mode, ``gtfobins`` provides ``pwncat`` a way to generically refer to file
read and write operations without depending on specific remote binaries being available.
The likelihood of no methods of file read being available on a remote system is very low,
however the probability of something like ``dd`` to be missing (however odd that would be)
is much higher. In this way, things like ``pwncat.victim.open`` can operate in a generic
way without resulting in dependencies on specific remote binaries.

Further, the ``gtfobins`` modules has abstracted away the idea of SUID and sudo to provide a
uniform interface for generating payloads which gain file read/write or shell with known
SUID or sudo privileges. The ``gtfobins`` module knows how and where to insert special options
to enable taking advantage of SUID binaries and also knows how to parse sudo command
specifications to enumerate available binaries and produce payloads compatible with the given
sudo specification.

Module Organization
-------------------

The GTFObins module is at it's core a database lookup. Currently, this database is a JSON
file which generically describes a large subset of the greater GTFObins project and
describes how to build payloads for each binaries different capabilities.

The top-level module (the ``GTFOBins`` class) provides access to this database. It is
initialized with a path to the database file (``data/gtfobins.json``) and callable
which represents the ``which`` application for the target system. It should resolve
binary names into their fullpaths on the remote system. It also takes a second boolean
parameter which indicates where the returned string should be quoted as with ``shlex.quote``.

Payloads are generated from individual methods, which are all an implementation of the
``pwncat.gtfobins.Method`` class. A method is an implementation of a specific capability
for a specific binary. They contain the payload, command arguments, input and exit command
needed to execute a specific capability with a specific binary. These methods are defined
in the database, which will be described further down.

A ``pwncat.gtfobins.Binary`` object is instantiated for every binary described in the
database. Each binary is described simply by it's name and a list of methods taken
from the database. At a generic level, the binary doesn't know the path on the remote
system, which it will need to build a payload with any given method.

When enumerating methods, the ``Binary`` and ``GTFOBins`` objects will both return
instances of the ``MethodWrapper`` class. This class provides the actual payload
building mechanism. It is the glue that puts a specific binary path, SUID state and
sudo specification together with a specific ``Method`` object. You will not interact
with ``Method`` objects directly when using this module.

Retrieving a Method Wrapper
---------------------------

Method wrappers are created in three two ways. They can be built automatically by the
``GTFOBins`` object by iterating through all known binaries and using the provided
``which`` callable to locate valid remote binaries. This is done through the
``iter_methods`` function:

.. code-block:: python

    for method in pwncat.victim.gtfo.iter_methods(Capability.READ, Stream.ANY):
        print("We could read a file with {method.binary_path}!")

This works well when you don't need any special permissions, but just need to generate
a payload for a specific capability. You have no requirements beyond your capability.

However, sometimes you know a specific binary that you can use, but you're not sure
what you can do with it. This can happen when performing privilege escalation. Perhaps
you can run a specific binary as another user, but you'd like to leverage this for
more access. In this case, you can provide the binary path to the ``iter_binary``
method to iterate methods for that specific binary. In this case, the ``GTFOBins``
module will not utilize the ``which`` callable. It trusts you that the given binary
path you provided exists, and yields method wrappers for the capabilities you requested,
if any.

.. code-block:: python

    for method in pwncat.victim.gtfo.iter_binary("/bin/bash", Capability.ALL, Stream.ANY):
        print(f"We could perform {method.cap} with /bin/bash!")

The last way of generating a method wrapper is used when you know that a user can
run commands via sudo with a specific specification. You'd like to know if GTFObins can
provide any useful capabilities with this command. For this, you can use the
``iter_sudo`` method which will iterator over all methods which are capable of being
executed under the given sudo specification.

.. code-block:: python

    for method in pwncat.victim.gtfo.iter_sudo("/usr/bin/git log*", caps=Capability.ALL):
        print(f"You could perform {method.cap} with /usr/bin/git!")

``GTFOBins`` is able to parse the sudo command specification and identify if the allowed
parameters to the command overlap with the needed parameters for different methods. If
the specification is ``ALL`` or ends with an asterisk, this is often possible. If it doesn't,
then it will try to make the parameters fit the specification and decide if the
capabilitiy is feasible.

Generating a Payload by Capability
----------------------------------

Once you have identified a specific method (and have a method wrapper), generating a payload is
easy. The ``MethodWrapper`` class provides the ``build`` function which will be all components
of the payload. Each payload consists of three items:

* The base payload
* The input sent to the application
* The command used to exit the application

The base payload is the command sent to the target host which will trigger the action specified
by the method capability. The input is the a bytes object which is sent to the standard input
of the application to trigger the action. The command used to exit is a bytes object which when
sent to the applications standard input should cleanly exit the application and return the user
to a normal shell. The last two are optional, but may be required and should always be sent
if returned from ``build``. If a method doesn't need them, they will be empty bytes objects
and you can safely send them to the application anyway.

The ``build`` function takes variable arguments because the specific parameters required
for each capability are different:

* A SHELL capability requires the following arguments:
    - shell: the shell to execute
* A READ capability requires the following arguments:
    - lfile: the path to the local file to read
* A WRITE capability with a RAW stream requires the following arguments:
    - lfile: the path to the local file to write to
    - length: the number of bytes of data which will be written
* A WRITE capability with any other stream type requires:
    - lfile: the path to the local file to write to

In the case of a read payload, the content of the file is assumed to be sent to standard output
of the command executed via the base payload. For write payloads, the new content for the file
is sent to the standard input of the base payload command **after** any input data returned from
the ``build`` function and **before** sending the exit bytes.

Putting It All Together
-----------------------

There's a lot of information up above, so here's an example of using the GTFOBins module. For
file read and file write. First up, we will read the ``/etc/passwd`` file and print the name
of all users on the remote system:

.. code-block:: python

    from pwncat import victim

    try:
        # Find a reader from GTFObins
        method = next(victim.gtfo.iter_methods(caps=Capability.READ, stream=Stream.ANY))
    except StopIteration:
        raise RuntimeError("no available gtfobins readers!")

    # Build the payload
    payload, input_data, exit_cmd = method.build(lfile="/etc/passwd")

    # Run the payload on the remote host.
    pipe = self.subprocess(
        payload,
        "r",
        data=input_data.encode("utf-8"),
        exit_cmd=exit_cmd.encode("utf-8"),
        name=path,
    )

    # Wrap the pipe in the decoder for this method (possible base64)
    with method.wrap_stream(pipe) as pipe:
        for line in pipe:
            line = line.decode("utf-8").strip()
            print("Found user:", line.split(":")[0])

This might seem long and laberous, but it is infinitely better than depending on a specific
file read method or attempting to account for multiple read methods each time you want to read
a file (although, luckily ``pwncat.victim.open`` already wraps this for you ;). Next, we'll
take a look at writing a file.

.. code-block:: python

    from pwncat import victim

    # The data we will write
    data = b"Hello from a new file!"

    try:
        # Find a writer from GTFObins
        method = next(victim.gtfo.iter_methods(caps=Capability.WRITE, stream=Stream.RAW))
    except StopIteration:
        raise RuntimeError("no available gtfobins readers!")

    # Build the payload
    payload, input_data, exit_cmd = method.build(lfile="/tmp/new-file", length=len(data))

    # Run the payload on the remote host.
    pipe = self.subprocess(
        payload,
        "w",
        data=input_data.encode("utf-8"),
        exit_cmd=exit_cmd.encode("utf-8"),
        name=path,
    )

    with method.wrap_stream(pipe) as pipe:
        pipe.write(data)


GTFOBins Utility Classes
------------------------

.. autoclass:: pwncat.gtfobins.Capability
    :members:

.. autoclass:: pwncat.gtfobins.Stream
    :members:

The GTFOBins Object
-------------------

.. autoclass:: pwncat.gtfobins.GTFOBins
    :members:

The MethodWrapper Object
------------------------

.. autoclass:: pwncat.gtfobins.MethodWrapper
    :members:

.. _GTFOBins: https://gtfobins.github.io