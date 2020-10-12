#!/usr/bin/env python3
from io import IOBase
from pathlib import Path
import collections
import itertools
import inspect
import fnmatch

from rich.progress import Progress
from rich import markup

import pwncat.modules
from pwncat import util
from pwncat.util import console
from pwncat.modules.enumerate import EnumerateModule


def strip_markup(styled_text: str) -> str:
    text = markup.render(styled_text)
    return text.plain


def list_wrapper(iterable):
    """ Wraps a list in a generator """
    yield from iterable


def FileType(mode: str = "r"):
    def _file_type(path: str):

        if path is None:
            return None

        if isinstance(path, IOBase):
            return path

        try:
            return open(path, mode)
        except (FileNotFoundError, PermissionError):
            raise ValueError(f"{path}: unable to open with mode: {mode}")

    return _file_type


class Module(pwncat.modules.BaseModule):
    """
    Perform multiple enumeration modules and write a formatted
    report to the filesystem.
    """

    ARGUMENTS = {
        "output": pwncat.modules.Argument(
            FileType("w"),
            default=None,
            help="The file to write a markdown report to (default: stdout)",
        ),
        "modules": pwncat.modules.Argument(
            pwncat.modules.List(str),
            default=["*"],
            help="List of modules to run (default: all)",
        ),
        "types": pwncat.modules.Argument(
            pwncat.modules.List(str),
            default=[],
            help="List of enumeration types to collect (default: all)",
        ),
        "clear": pwncat.modules.Argument(
            bool, default=False, help="Clear the cached results of all matching modules"
        ),
    }
    PLATFORM = pwncat.platform.Platform.ANY

    def run(self, output, modules, types, clear):
        """ Perform a enumeration of the given moduels and save the output """

        module_names = modules

        # Find all the matching modules (use set to ensure uniqueness)
        modules = set()
        for name in module_names:
            modules = modules | set(
                pwncat.modules.match(f"enumerate.{name}", base=EnumerateModule)
            )

        if clear:
            for module in modules:
                yield pwncat.modules.Status(module.name)
                module.run(progress=self.progress, clear=True)
            pwncat.victim.session.commit()
            pwncat.victim.reload_host()
            return

        # Enumerate all facts
        facts = {}
        for module in modules:

            if types:
                for pattern in types:
                    for typ in module.PROVIDES:
                        if fnmatch.fnmatch(typ, pattern):
                            # This pattern matched
                            break
                    else:
                        # This pattern didn't match any of the provided
                        # types
                        continue
                    # We matched at least one type for this module
                    break
                else:
                    # We didn't match any types for this module
                    continue

            # update our status with the name of the module we are evaluating
            yield pwncat.modules.Status(module.name)

            # Iterate over facts from the sub-module with our progress manager
            for item in module.run(progress=self.progress, types=types):
                if output is None:
                    yield item
                elif item.type not in facts:
                    facts[item.type] = [item]
                else:
                    facts[item.type].append(item)

        # We didn't ask for a report output file, so don't write one.
        # Because output is none, the results were already returned
        # in the above loop.
        if output is None:
            return

        yield pwncat.modules.Status("writing report")

        with output as filp:

            filp.write(f"# {pwncat.victim.host.ip} - Enumeration Report\n\n")
            filp.write("Enumerated Types:\n")
            for typ in facts:
                filp.write(f"- {typ}\n")
            filp.write("\n")

            for typ in facts:

                filp.write(f"## {typ.upper()} Facts\n\n")

                sections = []
                for fact in facts[typ]:
                    if getattr(fact.data, "description", None) is not None:
                        sections.append(fact)
                        continue
                    filp.write(
                        f"- {util.escape_markdown(strip_markup(str(fact.data)))}\n"
                    )

                filp.write("\n")

                for section in sections:
                    filp.write(
                        f"### {util.escape_markdown(strip_markup(str(section.data)))}\n\n"
                    )
                    filp.write(f"```\n{section.data.description}\n```\n\n")
