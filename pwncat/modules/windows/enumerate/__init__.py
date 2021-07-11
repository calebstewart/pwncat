#!/usr/bin/env python3
from typing import List, Callable

from pwncat.facts.windows import PowershellFact
from pwncat.platform.windows import Windows, PowershellError
from pwncat.modules.enumerate import Schedule, EnumerateModule


def build_powershell_enumeration(
    types: List[str],
    schedule: Schedule,
    command: str,
    docstring: str,
    title: Callable = None,
    description: Callable = None,
    single: bool = False,
):
    """
    Build an enumeration module around a single powershell command.
    This will construct and return an enumeration class which executes
    the given powershell script and yields a fact with the given types
    that exposes all properties of the returned powershell objects. This
    is a helper to quickly develop basic powershell-based enumeration modules.
    """

    class Module(EnumerateModule):

        PROVIDES = types
        PLATFORM = [Windows]
        SCHEDULE = schedule

        def enumerate(self, session: "pwncat.manager.Session"):

            try:
                result = session.platform.powershell(command)

                if not result:
                    return

                if isinstance(result[0], list):
                    results = result[0]
                else:
                    results = [results[0]]

                if single:
                    yield PowershellFact(
                        source=self.name,
                        types=types,
                        data=results[0],
                        title=title,
                        description=description,
                    )
                else:
                    yield from [
                        PowershellFact(
                            source=self.name,
                            types=types,
                            obj=obj,
                            title=title,
                            description=description,
                        )
                        for obj in results
                    ]

            except PowershellError as exc:
                pass

    # Set the docstring
    Module.__doc__ = docstring

    return Module
