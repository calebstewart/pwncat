Enumeration
===========

Enumeration in ``pwncat`` is achieved through the ``enumerate.*`` modules. All these modules
implement a sub-class of the standard ``pwncat`` module. Each enumeration can be run
individually or you can use one of the automated enumeration groups. Enumeration modules can
specify the their "schedule" which affects when they are run. By default, enumeration modules
run only once and their results are cached in the database. Some modules specify a "per-user"
schedule which means they run once per user. A smaller number of modules specify a "always"
schedule which means that every time you run the module it will execute that enumeration
regardless of any cached entries.

Gathering Enumeration Data
--------------------------

The ``enumerate.gather`` module is used to gather enumeration facts from all other
enumeration modules. Facts can be filtered by the module name or the types of facts.
This can be used to create a custom enumeration report.

.. code-block:: bash

   # Enumerate only SUID and File Capability enumeration types
   (local) pwncat$ run enumerate.gather types=file.suid,file.caps
   # Enumerate facts from all available modules
   (local) pwncat$ run enumerate.gather

The ``enumerate.quick`` module enumerates some useful types of enumeration data, but
is intended to not take much time. Both ``enumerate.gather`` and ``enumerate.quick``
implement the ``output`` parameter which allows you to write the enumeration results
to a markdown file instead of standard output.

.. code-block:: bash

   # Output a markdown formatted report to results.md
   (local) pwncat$ run enumerate.auto output=results.md
