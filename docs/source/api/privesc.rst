Privilege Escalation Modules
============================

Privilege Escalation is implemented using modules. Each privilege escalation
module is a sub-class of the ``EscalateModule`` class. The escalate module's
primary purpose is to enumerate possible escalation techniques. Techniques
are objects which implement specific escalation capabilities and can be put
together to form a fully-functional code execution primitive. Each technique
may implement file read, file write or shell/exec capabilities. The base
escalate module will collect all available techniques and attempt to use them
together to achieve the requested action.

Running an escalation module with no arguments simply returns an `EscalateResult`
which wraps a list of techniques. This result can be used to attempt file read,
file write or execution as the requested user. All escalate modules accept three
boolean arguments which indicate it should attempt one of ``read``, ``write`` or
``exec``. If any of these arguments are true, the requested action will be
attempted instead of returning the result.

When implementing an escalate module, any errors should be signaled by the
``EscalateError`` exception.

Automatic Privilege Escalation
------------------------------

The ``escalate.auto`` module (aliased to simply ``escalate``) will attempt to use
any available module to escalate to the desired user. Further, it will recursively
attempt escalation through as many users as needed to find a path to the requested
user. This module simply aggregates the results from all available escalation
modules and then attempts the escalation with the available techniques. If direct
escalation to the requested user is not possible, it will attempt escalation to
eacho ther user available and recurse to find a path to the requested user.

This is the most common way to attempt privilege escalation, as it can quickly
attempt multiple different escalation options through multiple users. However,
if you know a likely vulnerability, you can execute an individual escalate module
directly in the same way.

Any extra arguments passed to the ``escalate.auto`` module will be passed on to
any module it executes. This allows modules with custom arguments to be included
in the automatic escalation attempts. However, this can be problematic. If two
modules have arguments with the same name and different required values, at least
one of them will fail to run. As a result, you cannot count on ``escalate.auto``
to be able to attempt any module which requires custom arguments.

As with standard escalate modules, ``escalate.auto`` will by default simply return
the escalate result containing all techniques it found. These techniques will span
multiple modules. This makes it easy to quickly enumerate all known possible
escalation paths.

Module Structure
----------------

Escalate modules at their core are a sub-class of ``BaseModule``. As such, you can
define custom arguments and platform requirements. If custom arguments are required,
you must include the ``EscalateModule`` arguments in your definition as noted in the
class reference below.

.. code-block:: python

    class Module(EscalateModule):
        """ Simple example module that does nothing. """

        # Define supported platform(s)
        PLATFORM = Platform.LINUX
        # Default priority is 100. Higher value = lower priority. Must be > 0.
        PRIORITY = 100
        # Custom arguments. Remove this entirely if unneeded.
        ARGUMENTS = {
            **EscalateModule.ARGUMENTS,
            "custom_arg": Argument(str),
        }

        def enumerate(self, user, custom_arg):
            """ Implement a generator of Technique's """

            # Technique implementation is what does the work of an
            # escalate method. You should implement a technique class
            # specific to your module.
            # yield YourCustomTechnique(Capability.SHELL, "root", self)

        def human_name(self, tech: YourCustomTechnique):
            """ Create a pretty-printed representation of this module/technique """
            return "a really cool custom technique"

Implementing A Technique
------------------------

Techniques are the heart and soul of an escalation module. ``pwncat`` uses
techniques with different capabilities together to attempt to perform various
actions. For example, if you request file read, ``pwncat`` may use a ``exec``
technique to gain a shell, and then read the file normally. Alternatively,
attempting ``exec`` may require ``pwncat`` to use ``read`` and ``write``
techniques to escalate privileges.

An individual technique is identified by a ``Capability``, a user name, and a
module. The capabilities are taken from ``pwncat.gtfobins`` and include things
such as file read, file write or shell. There are associated methods within a
technique to execute these various capabilities and these are the methods you
must implement depending on the techniques supported capabilities. The module
is simply your module that created the technique. The user represents the name
of the user which this technique allows access as. For example, for a SETUID
binary, the user would be the owner of the binary itself.

Here is an example of a skeleton technique class:

.. code-block:: python

    # This decorator is not required, but if your technique may
    # result in a EUID vs RUID mismatch, use this decorator to
    # correct this issue automatically if needed.
    @euid_fix
    class YourCustomTechnique(Technique):
        """ Implement the various capabilities your module provides """

        def exec(self, binary: str) -> str:
            """ Called for techniques which provide Capability.SHELL.
            Execute the specified shell the other user, and return a
            string which will exit the shell and return to the current
            state. """

        def write(self, filepath: str, data: bytes):
            """ Called for techniques which provide Capability.WRITE.
            Write ``data`` to the specified file as the other user. """

        def read(self, filepath: str):
            """ Called for techniques which provide Capability.READ.
            Open the remote file for reading and return a file-like
            object which yields it's contents. """

Utility Classes and Functions
-----------------------------

.. autofunction:: pwncat.modules.escalate.euid_fix

.. autoclass:: pwncat.modules.escalate.GTFOTechnique

.. autoclass:: pwncat.modules.escalate.FileContentsResult
   :members:

.. autoclass:: pwncat.modules.escalate.EscalateChain
   :members:

.. autoclass:: pwncat.modules.escalate.EscalateResult
   :members:

Technique Base Class
--------------------

.. autoclass:: pwncat.modules.escalate.Technique
   :members:

Escalate Module Base Class
--------------------------

.. autoclass:: pwncat.modules.escalate.EscalateModule
   :members:
