Command Parser
==============

The local ``pwncat`` prompt and scripting configuration language are powered by the ``CommandParser``
class which is responsible for parsing lines of text, extracting arguments, and dispatching them
to the appropriate command.

Commands are loaded automatically through the ``pkgutils`` module in Python from the ``pwncat/commands``
directory. Every Python file from this directory is loaded as a module and checked for a ``Command``
attribute. This attribute must be a class which inherits from the ``pwncat.commands.base.CommandDefinition``
class. This class defines the structure of a command and allows the ``CommandParser`` to intelligently
create ``argparse`` objects, syntax highlighting lexers, and ``prompt_toolkit`` completers for your
commands.

To create a new command, simply create a python file under the ``pwncat/commands`` directory. The name
can be anything that conforms to python module naming standards. As an example, the ``sysinfo`` command
is fairly straightforward:

.. code-block:: python

    #!/usr/bin/env python3
    from pwncat.commands.base import CommandDefinition, Complete, Parameter
    from pwncat.util import console
    import pwncat


    class Command(CommandDefinition):
        """
        Display remote system information including host ID, IP address,
        architecture, kernel version, distribution and init system. This
        command also provides the capability to view installed services
        if the init system is supported by ``pwncat``.
        """

        PROG = "sysinfo"
        ARGS = {
            "--services,-s": Parameter(
                Complete.NONE, action="store_true", help="List all services and their state"
            )
        }

        def run(self, args):

            if args.services:
                for service in pwncat.victim.services:
                    if service.running:
                        console.print(
                            f"[green]{service.name}[/green] - {service.description}"
                        )
                    else:
                        console.print(f"[red]{service.name}[/red] - {service.description}")
            else:
                console.print(f"Host ID: [cyan]{pwncat.victim.host.hash}[/cyan]")
                console.print(
                    f"Remote Address: [green]{pwncat.victim.client.getpeername()}[/green]"
                )
                console.print(f"Architecture: [red]{pwncat.victim.host.arch}[/red]")
                console.print(f"Kernel Version: [red]{pwncat.victim.host.kernel}[/red]")
                console.print(f"Distribution: [red]{pwncat.victim.host.distro}[/red]")
                console.print(f"Init System: [blue]{pwncat.victim.host.init}[/blue]")

This is a simple command that will print system information from the host database and provide
the capability to view installed services, provided the init system is supported. This command also shows a
basic example of interacting with the remote victim. The ``pwncat.victim`` object allows you to
interact abstractly with the currently connected victim. The ``LOCAL`` property tells the ``CommandParser``
whether this command operates only on local resources. If set to true, the command will be allowed
to run prior to a connected victim. In this case, we interact directly with the victim, and therefore
set the ``LOCAL`` property to false.

Command Arguments
-----------------

Argument parsing is achieved using the python built-in module ``argparse``. The parser is automatically
created based on the ``ARGS``, and ``DEFAULTS`` dictionaries defined in your ``Command`` class.

``DEFAULTS`` is a dictionary mapping argument names to default values. This is passed directly to
the ``argparse.ArgumentParser.set_defaults`` method. This allows you to set defaults for values which
can't be set in the argument definition (such as values referenced in multiple arguments with
`dest` parameter).

The ``ARGS`` property is a dictionary which matches argument names to the ``parameter`` objects.
The key for this dictionary is a string representing the a comma-separated list of parameter
names (e.g. "--param,-p"). The values in this dictionary are built from the ``parameter`` method
imported above:

.. code-block:: python

    def parameter(complete, token=Name.Label, *args, **kwargs):

The first parameter is one of the ``pwncat.commands.base.Complete`` enumeration items. Which includes
things like ``Complete.REMOTE_FILE``, ``Complete.LOCAL_FILE``, ``Complete.CHOICES`` and ``Complete.NONE``.
For parameters with no argument ("switches"), this should be ``Complete.NONE``. This controls how
the CommandParser tab-completes your command at the local prompt.

The second parameter is the Pygments token which this option should be highlighted with. Normally,
you can leave this as default, but you may change it if you like. The remaining arguments are passed
directly to ``argparse.ArgumentParser.add_argument``.

Command Helpers
---------------

.. autoclass:: pwncat.commands.base.Complete
    :members:

.. autofunction:: pwncat.commands.base.parameter

.. autoclass:: pwncat.commands.base.StoreConstOnce

.. autofunction:: pwncat.commands.base.StoreForAction

.. autofunction:: pwncat.commands.base.RemoteFileType

CommandDefinition Object
------------------------

.. autoclass:: pwncat.commands.base.CommandDefinition
    :members:
