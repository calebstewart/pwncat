Windows Support
===============

Starting with ``v0.4.0a1``, pwncat supports multiple platform targets. Specifically,
we have implemented Windows support. Windows support is complicated, as a majority
of interaction cannot be simply executed from a shell, and parsed. As a result, we
implemented a very minimal C2 framework, and had pwncat automatically upload and
execute this framework for you. **You only need to provide pwncat a cmd or
powershell prompt**.

Goals
-----

When building out Windows support, there were a lot of options. We had to filter out
these options based on the goals for the C2. We whittled these goals down to the
following:

- Automatically Bypass AMSI
- Automatically Bypass AppLocker
- Undetected by Defender
- Automatically Bypass PowerShell Constrained Language Mode
- Provide the user with an interactive shell
- Support structured interaction for automation
- Touch disk as little as possible

This was a tall order, and doing so generically was difficult. I'll talk about our
solution to each of those problems. Firstly, AMSI was easy. Once everything was set
in place, we could use the standard .Net reflection to bypass AMSI relatively easily.

This brought up another issue: Constrained Language Mode. In PowerShell, if constrained
language mode is active, we effectively have no access to .Net. This presents serious
problems. The only way we could find to bypass Constrained Language Mode without
depending on PowerShell v2 was to execute .Net code. From within .Net, we can reflectively
modify the PowerShell implementation, and spawn an interactive session in Full Language
Mode regardless of environment or Group Policy settings.

With the need to execute .Net without reflective loading from PowerShell (due to CLM),
we now break one of our rules. We have to upload a file to disk to execute, and with
that we run into both Defender and AppLocker. For AppLocker, there is a list of safe
directories where we can place a binary, and load it with the .Net ``InstallUtil``
tool. This provides a way around AppLocker. Further, we implemented a small stager
which simply waits and downloads more .Net code to be reflectively loaded. This
mitigates the files on disk by making the only on-disk file a simple stager with low
equity. It also makes the file on disk less likely to trigger Defender.

At this point, we can load stage two which implements the required structured
interaction and interactive shell as needed, and have met all goals listed above
with a slight compromise on files touching disk. To make things as smooth as possible,
pwncat will automatically remove the stageone DLL when exiting.

Communication Protocol
----------------------

After initializing stage two, pwncat communicates over Base64-encoded GZip blobs.
Each command sent is a JSON-encoded argument array specifying the type name,
method name, and subsequent arguments for a static method within stage two. The
JSON data is deserialized so you can pass any serializable type to a method natively
from pwncat.

Responses are formatted in the same way as requests, except are returned as a dictionary.
The dictionary looks like this:

.. code-block:: json

    {
        "error": 0,
        "result": {},
        "message": ""
    }

If a method fails, the error property will be non-zero, and the ``message`` property
will be present containing a description of the failure. If the method succeeds, the
``result`` property will contain the return value of the method. This value could be
any JSON serializable type (the example above shows an empty dictionary but it could
just as easily be a bare integer).

The Windows platform provides a helper method to call methods which seamlessly translates
Python calls to method calls. The return value is the ``result`` property, and a
:class:`pwncat.platform.windows.Windows.ProtocolError` will be raised if there was an error.

.. code-block:: python

    result = session.platform.run_method("PowerShell", "run", "[PSCustomObject]@{ thing = 5; }", 1)
    # Prints "5"
    print(result[0]["thing"])

There are also other abstractions within the framework for common operations like executing
PowerShell. For more information on the API of the Windows platform, please see the
API Documentation.

Plugin API
----------

You can utilize the pwncat API to load third-party .Net assemblies from the attacker machine
and easily execute their methods. The stage two C2 provides the ability to load an assembly
and retrieve a unique identifier for the loaded assembly. You can then use this identifier
to execute methods from the assembly in a similar way to the ``run_method`` method above.

The plugins themselves must implement a specific API in order to be compatible. A basic
plugin looks like this:

.. code-block:: csharp

    using System.Reflection;

    class Plugin
    {
        public static void entry(Assembly stagetwo)
        {
            // Optional method; executing while loading the plugin
        }

        public static string test(string arg1, int arg2)
        {
            // A method that can be called from the C2
            return "Hello " + arg1 + " " + arg2.ToString();
        }
    }

If you had compiled this plugin to a dll named ``example.dll``, you could load and execute it
with the following from pwncat:

.. code-block:: python

    example = session.platform.dotnet_load("example.dll")
    # this prints "Hello Plugin 42"
    print(example.test("Plugin", 42))

The Windows platform will deduplicate plugins by name and by file hash to ensure individual
assemblies are only loaded once. If a given assembly has already been loaded, the existing
:class:`pwncat.platform.windows.Windows.DotNetPlugin` instance will be returned instead of
reloading the existing assembly.
