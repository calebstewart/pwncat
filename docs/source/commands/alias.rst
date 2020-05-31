Alias
=====

``alias`` is a simple command. It provides the ability to rename any built-in command. Unlike aliases in common shells,
this does not allow you to provide default parameters to commands. Instead, it simply creates an alternative name.

You can specify a new alias simply by providing the new name followed by the new name. For example, to alias "download"
to "down", you could do this in your configuration script:

.. code-block:: bash

    alias down "download"

``alias`` takes as it's second argument a string. Passing anything else (e.g. a code block) will not produce the desired
results. The command you are aliasing must exist and be a standard command (no aliases to other aliases are supported).