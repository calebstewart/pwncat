Configuration
=============

Configuration in ``pwncat`` is tracked in the ``pwncat.config`` object. This object
acts similar to a dictionary with some extra features. Specifically, this object
implements type checking, and understands/tracks module context.

There is a module named ``pwncat.config`` which contains some helper-types, but
generally should not be needed. It is masked behind an object defined in ``pwncat/__init__.py``
named ``config``. The ``pwncat.config`` object is of the type ``pwncat.config.Config``.

When used as a dictionary, only setting local values (specific to a module context) is
supported. Therefore, the following is valid within a module context:

.. code-block:: python

   import pwncat
   pwncat.config["lhost"] = "10.10.10.10"

If you would like to set global configuration items, you must use the ``set`` method:


.. code-block:: python

   import pwncat
   pwncat.config.set("lhost", "10.10.10.10", glob=True)

When retreiving values, the preference is always for local module-context values. If
no module-specific values are set, then the global value is returned. You can use the
dictionary syntax for this:

.. code-block:: python

   import pwncat
   username = pwncat.config["backdoor_user"]

To add available global configuration items, you can add items to the ``pwncat.config.values``
dictionary. This dictionary maps configuration names to another dictionary. The structure
looks like this:

.. code-block:: python

   pwncat.config.values["config_name"] = {
        "value": "default or current value",
        "type": callable_converting_string_to_correct_type
   }

The ``type`` property should be a callable which converts the input (normally a string``
to the required type. If the required type is passed in, it should be returned unchanged.
If the provided value is invalid, a ``ValueError`` should be raised.

If the value is a script (such as ``on_load``), the type will be a regular string. In this
case, the string is literally a script which will be evaluated upon some condition.

Key Bindings
------------

Key bindings are handled separately from standard configuration items. They are managed
with the same configuration object, but are retrieved using the ``binding`` method. This method
takes either a string representing the name of the key or a bytes object representing the
raw key-codes. The keybindings are stored in the ``pwncat.config.bindings`` dictionary which
maps ``KeyType`` objects to the script which executes upon their press.

This is mainly a UI/end-user function, and therefore the only clean method of modifying this
dictionary at the moment is through the ``set`` command. This may change in the future.
