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

The base ``enumerate`` module is an alias of ``enumerate.gather``. This module is used to
gather enumeration facts from all other enumeration modules. Facts can be filtered by the
module name or the types of facts.

.. code-block:: bash

   # Enumerate only SUID and File Capability enumeration types
   (local) pwncat$ run enumerate types=file.suid,file.caps
   # Enumerate facts from all available modules
   (local) pwncat$ run enumerate

Generating A Target Report
--------------------------

The ``report`` module utilizes the enumeration framework to generate formatted host reports.
When run without any arguments, this module will gather interesting host details and render
a report to the terminal. Optionally, you can specify an output file name which where a
Markdown report will be written.

The default report templates can be found in ``pwncat/data/reports``.

.. code-block:: bash

   # Generate formatted report
   (local) pwncat$ run report
   # Generate a markdown report
   (local) pwncat$ run report output=report.md
