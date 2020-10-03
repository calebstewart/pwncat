Modules
=======

``pwncat`` is extended primarily by implementing modules. This concept is similar in theory to Metasploit modules. Modules are organized by their purpose, so modules for persistence are under the ``persist`` package while modules for enumeration are under the ``enumerate`` package.

At their core, modules are simply classes which implement a ``run`` function to perform some task. Modules can have arguments which are passed as normal keyword arguments to the ``run`` method. Argument names, types and documentation is stored in the class property ``ARGUMENTS`` which is a dictionary mapping argument names to ``Argument`` instances.

When a user executes the following commands at the local prompt:

.. code-block::

   use persist.cron_reverse
   set lhost 10.0.0.1
   set lport 4444
   run

``pwncat`` will first lookup the Python module ``pwncat.modules.persist.cron_reverse``. This module must implement a class named ``Module`` which inherits from the ``BaseModule`` class. Next, each ``set`` call will cross-reference the parameter name with the module arguments and ensure type-checking is performed. Lastly, the ``run`` method will be executed.

Return values from modules are displayed in two ways. First, if the return value conforms to the ``Result`` interface, it is formatted and displayed with a title and description under the appropriate category. Otherwise, a list of uncategorized results will be displayed. If no return value is found, a simple "Module completed successfully" message will be displayed.

Creating Base Modules
---------------------

Specilized categories such as ``enumerate``, ``persist``, and ``escalate`` have their own module base classes which all inherit from the ``BaseModule`` class. If you'd like to create a generic module which does not fit into these categories, you can subclass the ``BaseModule`` class itself.

A basic module is placed anywhere under the ``pwncat/modules/`` package. It will be automatically loaded upon opening ``pwncat``. A basic module named "random_string.py" could be placed under "pwncat/modules" and may look like this:

.. code-block:: python

   class Module(BaseModule):
       """
       Module documentation. This is shown with the `info` command.
       """

       ARGUMENTS = {
           "length": Argument(type=int, default=10, help="How long to make the string"),
           "alphabet": Argument(type=str, default=string.ascii_printable, help="The characters to choose from")
       }
  
       def run(self, length, alphabet):
           return "".join([random.choice(alphabet) for _ in range(length)])

This module simply generates a random string of a given length and can be executed in a few different ways at the pwncat prompt:

.. code-block::

   use random_string
   set length 5
   set alphabet 0123456789abcdef
   run
   # Or, more succinctly
   run random_string length=5 alphabet=0123456789abcdef

This module can also be used from within ``pwncat`` by using the ``pwncat.modules`` helper functions to locate and run modules by name:

.. code-block:: python

   import pwncat.modules
   result = pwncat.modules.run("random_string", length=5, alphabet="0123456789abcdef")
   result = list(pwncat.modules.match("random_.*"))[0].run(length=2, alphabet="hello")
   result = pwncat.modules.find("random_string").run(length=2, alphabet="hello")

Module Results
--------------

Module `run` methods should return result objects which are compatible with the `pwncat.modules.Result` object. How those values are returned can happen in a few ways. For simple modules, the `run` method can simply return the result with the `return` statement. In this case, no progress bar will be created and until the module finishes there will be no status output. Alternatively, if the `run` method is a generator, a progress bar is automatically created using `rich` and the status is updated with each of the `yield`'d values. The results should always have a `__str__` operator defined so that status results can be printed properly. The result of the `run` method will never be a generator when called externally, however. The base module class wraps the subclass `run` method, creates a progress bar, collects the output and returns an interable object containing all of the results.

If a module would like to update the current progress status without returning any data, it can do so using the `pwncat.modules.Status` type. If an object of this type is `yield`'d, it will not be added to the resulting return value of `run`, and will only update the progress bar. The `Status` class is simply a subclass of `str`, therefore issuing `yield Status("new module status")` will update the progress bar accordingly.

If you need to implement a custom result class to encapsulate your results, you can do so either by directly inheriting from the `Result` class or by simply implementing the required methods. The only strictly required methods are either the `title` or `__str__` methods. By default, the `title` method will simply return `str(self)`, so overriding `__str__` is normally enough. This controls the single-line output of this result on the terminal.

For objects which require larger output, you can utilize the `description` method. This method returns a string with a long-description of your object. For example, the `private_key` enumeration data implements this method to show the entire content of the private key while the title just indicates that it *is* a private key and where it was found. 

Lastly, there is a `category` method which specifies how to categorize this result. The affects how the data is separated and displayed when run from the prompt. 

Other methods or properties can be added at will to this object. The above methods are not meant to obstruct the programmatic use of the data returned by a module so that you can organically return results from modules while still having properly formatted output from the prompt.

Recursively Calling Modules
---------------------------

If your new module needs to call another module (through any of the interfaces above), you should be sure to pass the current progress bar down to the sub-modules. This is done like so:

.. code-block:: python

   class Module(BaseModule):
       def run(self):
           result = pwncat.modules.run("some.other.module", progress=self.progress)

This ensures that multiple progress bars are not created and fighting over the terminal lock.

Exceptions
----------

.. autoclass:: pwncat.modules.ModuleNotFound

.. autoclass:: pwncat.modules.ArgumentFormatError

.. autoclass:: pwncat.modules.MissingArgument

.. autoclass:: pwncat.modules.InvalidArgument

.. autoclass:: pwncat.modules.ModuleFailed

Module Helper Classes
---------------------

.. autoclass:: pwncat.modules.Argument
   :members:

.. autofunction:: pwncat.modules.List

.. autofunction:: pwncat.modules.Bool

.. autoclass:: pwncat.modules.Status

.. autoclass:: pwncat.modules.Result
   :members:

Locating and Using Modules
--------------------------

.. autofunction:: pwncat.modules.reload

.. autofunction:: pwncat.modules.find

.. autofunction:: pwncat.modules.match

.. autofunction:: pwncat.modules.run

Base Module Class
-----------------

.. autoclass:: pwncat.modules.BaseModule
    :members:
    :undoc-members:
