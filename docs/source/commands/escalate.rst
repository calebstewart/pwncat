Escalate
========

The escalate command is used to perform automated escalation. As described in the privilege escalation
section, this command is capable of perform recursive escalation across multiple users and sessions. It
will also utilize any installed local implants as needed to escalate to the requested user.

.. code-block:: bash

    # List direct escalations from the current user to any user
    escalate list
    # List direct escalations from the current user to root
    escalate list -u root
    # Attempt escalation by any means to root
    escalate run
    # Attempt escalation by any means to john
    escalate run -u john
