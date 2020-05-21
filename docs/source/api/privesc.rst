Privilege Escalation Modules
============================

Privilege escalation in ``pwncat`` is implemented using a pluggable privilege escalation framework
which allows new methods to be easily implemented and integrated into ``pwncat``. All privilege
escalation methods inherit from the ``pwncat.privesc.base.Method`` class and are implemented under
the ``pwncat/privesc`` directory.

Methods vs Techniques
---------------------

Privelege escalation methods may implement multiple techniques. Techniques represent a single action
which a specific privilege escalation method can perform. Each technique is identified by it's method,
the user which the action can be performed as, a Capability and some method specific data.

Capabilities are one of ``READ``, ``WRITE`` or ``SHELL`` and are specified with the
``pwncat.gtfobins.Capability`` flags. Each technique must specify one and only one capability.

Privilege escalation is implemented by iterating over all known methods and enumerating all techniques.
After techniques are gathered, ``pwncat`` attempts to put the different file read, write or shell
techniques together to perform some action. For example, it might use a shell technique to.. well...
get a shell. However, ``pwncat`` may also attempt to read a file with a shell technique or gain a
shell with a file read technique. The individual privilege escalation methods do not need to worry
about this, though. They only need to enumerate all available techniques and implement the
associated execution methods for those techniques.

Implementing a Privilege Escalation Method
------------------------------------------

Privilege escalation methods normally take the form of common vulnerabilities or misconfigurations
in the target host. For example, there are built-in privesc methods for SUID binaries, sudo privileges
and a few common vulnerabilities. Each method implements up to five different class methods.

The first method is the ``check`` method. This is a ``classmethod`` which simply tests to make sure
that the dependencies of this privesc method are available. It should check that the required
binaries, packages or libraries associated with this escalation are available. By default, the base
class will check that all binaries specified in the class variable ``BINARIES`` are present on the
remote system. If anything is missing from the remote system rendering this method unusable, the check
method should raise a ``PrivescError`` exception with a description of what is missing.

The next method is the ``enumerate`` method. This function returns a list of ``pwncat.privesc.base.Technique``
objects, each describing a technique which this method is capable of performing on the remote host.
For example, the SUID method iterates over all known SUID binaries and checks for file write, file
read or shell capabilities with GTFObins. It returns techniques which overlap with the capabilities
requested:

.. code-block:: python

    def enumerate(self, caps: Capability = Capability.ALL) -> List[Technique]:
        """ Find all techniques known at this time """

        # Update the cache for the current user
        self.find_suid()

        known_techniques = []
        for suid in pwncat.victim.host.suid:
            try:
                binary = pwncat.victim.gtfo.find_binary(suid.path, caps)
            except BinaryNotFound:
                continue

            for method in binary.iter_methods(suid.path, caps, Stream.ANY):
                known_techniques.append(
                    Technique(suid.owner.name, self, method, method.cap)
                )

        return known_techniques

The last three methods all take a parameter of a ``Technique`` object. This ``Technique`` will
be one of the techniques returned from ``enumerate`` by this method. They implement the three
capabilities which are possible. The first is the ``execute`` method. This method is used to
escalate privileges and gain a shell as the user specified in the technique. This type of
technique is returned, for example, from a SUID ``/bin/bash``, because we are able to directly
gain a shell as the owning user. It should perform the escalation and return with the remote
host currently at a prompt for the new user. If there are any issues or errors, it will raise a
``PrivescError`` with the description of the problem. The return value of this function is a
bytes object which can exit the terminal and return to the previous user. In a simple case, this
could be just "exit". In a more complicated case, like getting a shell from within ``vim``, this
may include control sequences to exit the shell and the containing application.

Next, methods can implement the ``read_file`` function. This function returns a file-like object
used to read data from a remote file as the user specified in the technique. This is possible,
for example in situations where a binary such as ``cat`` is SUID. Again, if there is an issue,
a ``PrivescError`` is raised.

The last method which may be implemented is the ``write_file`` method. This method will write
the given data to a file as the user specified in the technique. The method does not return
any data and should simply write the requested data using the technique specified.

Privilege Escalation Method Class
---------------------------------

.. autoclass:: pwncat.privesc.base.Method
    :members:

Technique Class
---------------

.. autoclass:: pwncat.privesc.base.Technique
    :members:
