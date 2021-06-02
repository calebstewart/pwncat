Automated Privilege Escalation
==============================

pwncat has the ability to locate and exploit privilege escalation vulnerabilities. The vulnerabilities
are identified through enumeration, and can be exploited through the ``escalate`` command. Internally,
pwncat has two types of escalation objects. Firstly, there are abilities. These are actions
which we are able to perform with the permissions of a different user on the target. The second type
of objects are escalations. Escalations utilize one or more abilities to achieve a session as the
targeted user.

As an example, abilities could be things such as:

* File Write
* File Read
* Binary execution

Escalations could be things such as:

* Executing a shell (the simplest option)
* Reading user private keys and ssh-ing to localhost
* Writing private keys
* Implanting a backdoor user in /etc/passwd (if file-write as root is available)

Invoking Privilege Escalation
-----------------------------

There are two ``escalate`` subcommands. In order to locate direct escalation vectors, you can use the
``list`` subcommand. This will use the enumeration framework to locate any escalations that may be
possible as the active user.

.. code-block:: bash

   # List direct escalations for any user
   (local) pwncat$ escalate list
   # List direct escalations to the specified user
   (local) pwncat$ escalate list -u root

Escalation can be triggered with the ``run`` subcommand. This command will first attempt to escalate
directly to the requested user. If no direct escalations are possible, it will try to recursively
escalate through other users based on the available direct escalations.

.. code-block:: bash

   # Escalate to root
   (local) pwncat$ escalate run
   # Escalate to a specified user
   (local) pwncat$ escalate run -u john
