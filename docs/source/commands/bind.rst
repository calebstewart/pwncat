Bind
====

The bind command is used to create new keyboard shortcuts or change old ones. Keyboard shortcuts are accessed by first
pressing your defined "prefix" key (by default: ``C-k``). ``bind`` takes two parameters: the key to bind, and the
script to run when it is pressed.

Key Selection
-------------

The key argument is specified as a string. If the string is a single character, it is assumed to be that literal printed
character. For example, to bind the lowercase "a" key to a command you could:

.. code-block:: bash

    bind "a" "some helpful command"

If the key argument is longer than one character, it is assumed to be a key name. The key names accepted by pwncat
are taken directly at runtime from the list of known ANSI keystrokes defined in the ``prompt_toolkit`` package. They
use the same syntax as in prompt toolkit. All key names are lowercase. The prompt_toolkit documentation covers the
keys supported by their module in their `documentation here`_. Any key defined by prompt_toolkit is available for
key binding by pwncat.

Script Content
--------------

The target of a key binding is a script. Scripts in pwncat can be specified as a string, which can only contain a
single command, or as a code block surrounded by curly braces. When in code block mode, you can use as many commands
as you like, and even insert comments, blank lines, etc.

.. code-block:: bash

    bind "a" {
        # you can bind a series of commands which you
        # do very often to a key, if you find it helpful.
        privesc -l
        persist -s
        tamper
    }

.. _`documentation here`: https://python-prompt-toolkit.readthedocs.io/en/master/pages/advanced_topics/key_bindings.html#list-of-special-keys