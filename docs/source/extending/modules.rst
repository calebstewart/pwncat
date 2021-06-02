Developing Modules
==================

Modules can exist anywhere on the filesystem as a Python package. By default,
they are located within the pwncat source at ``pwncat/modules/``. They are
organized by platform. For example, a Windows module for enumerating users
would be placed in ``module_directory/windows/enumerate/users.py``. The
directories underneath the module directory must be python packages, therefore
each directory must contain a ``__init__.py`` file. In order to load non-standard
modules, you can use the ``load`` command from the local prompt or a
configuration script.

Each module must inherit from the ``pwncat.modules.BaseModule`` class. Each
module has only one required method: ``run``. The run method takes a session
as the first argument followed by any named arguments in the ``ARGUMENTS``
dictionary. Named arguments should not have defaults set in the method definition.
The run method acts as a generator. Any results yielded from the module are
returned from the session's ``run`` method as an array. Each yielded object
should implement the ``pwncat.modules.Result`` class to be properly displayed
by the framework.

There are two required properties that must be defined. ``PLATFORM`` is a list
``pwncat.platform.Platform`` classes which are valid for this module. ``ARGUMENTS``
is a dictionary mapping argument names to instances of the ``pwncat.modules.Argument``
class. This class takes an argument type, default value and help string which are
displayed in the info output for a module.

The documentation for a module is taken from the docstring of the ``Module`` class.

Running Modules
---------------

Modules are executed on a specific session with the ``pwncat.manager.Session.run``
method. Keyword arguments are passed to the modules through this method. Any
required arguments not specified will be taken from the manager configuration if
there is a configuration with a matching name.

The ``Session.run`` will call the modules internal ``run`` method and process the
results. Each result will be displayed using the ``Result.title`` method to produce
a formatted description. A progress bar will be displayed while gathering the
module results, and then all results are returned. If a single result item is an
instance of ``pwncat.modules.Status``, the item is not added to returned list of
results, but is used to update the progress bar. This allows modules to seemlessly
show module status.

The ``run`` command simply calls ``Session.run`` and formats the output using the
``Result.title`` and ``Result.description`` methods of the results themselves
generically.

Enumerate Modules
-----------------

Enumeration modules are a special case of the base module. For enumeration modules,
you cannot override the ``run`` method. Instead, you should override the ``enumerate``
method. The ``enumerate`` method takes only a session as an argument, and should act
as a generator, yielding ``Fact`` objects to be added to the database.

Enumeration modules cannot specify arguments. They must still specify a platform.
Further, they should specify a ``SCHEDULE`` property which is one of the ``pwncat.modules.escalate.Schedule``
enumerations (``ONCE``, ``PER_USER``, ``ALWAYS``). This defines how often the
module is executed, since all results are cached.

Example Standard Module
-----------------------

.. code-block:: python
    :caption: Example Base Module

    class Module(BaseModule):
        """ Module Documentation """

        PLATFORM = [Linux]
        ARGUMENTS = { "arg": Argument(str, help="help string") }

        def run(self, session: "pwncat.manager.Session", arg: str):
            yield Status("A status message!")
            session.log(f"ran {self.name}")
