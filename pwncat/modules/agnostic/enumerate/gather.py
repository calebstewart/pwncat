#!/usr/bin/env python3
import fnmatch
import inspect
import itertools
import collections
from io import IOBase
from pathlib import Path

from rich import markup
from rich.progress import Progress

import pwncat.modules
from pwncat import util
from pwncat.util import console, strip_markup
from pwncat.modules import ModuleFailed
from pwncat.modules.enumerate import EnumerateModule


def list_wrapper(iterable):
    """Wraps a list in a generator"""
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
        "cache": pwncat.modules.Argument(
            bool,
            default=True,
            help="Return cached results along with new facts (default: True)",
        ),
    }
    PLATFORM = None

    def run(self, session, output, modules, types, clear, cache):
        """Perform a enumeration of the given moduels and save the output"""

        module_names = modules

        # Find all the matching modules (use set to ensure uniqueness)
        modules = set()
        for name in module_names:
            modules = modules | set(
                list(session.find_module(f"enumerate.{name}", base=EnumerateModule))
            )

        if clear:
            for module in modules:
                yield pwncat.modules.Status(module.name)
                module.run(session, clear=True)
            return

        # Enumerate all facts
        facts = {}

        if cache:
            for fact in session.target.facts:
                if not types or any(
                    any(fnmatch.fnmatch(t2, t1) for t2 in fact.types) for t1 in types
                ):
                    if output is None:
                        yield fact
                    elif item.type not in facts:
                        facts[item.type] = [item]
                    else:
                        facts[item.type].append(item)

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
            try:
                for item in module.run(session, types=types, cache=False):
                    if output is None:
                        yield item
                    elif item.type not in facts:
                        facts[item.type] = [item]
                    else:
                        for fact in facts[item.type]:
                            if fact == item:
                                break
                        else:
                            facts[item.type].append(item)
            except ModuleFailed as exc:
                session.log(f"[red]{module.name}[/red]: {str(exc)}")

        # We didn't ask for a report output file, so don't write one.
        # Because output is none, the results were already returned
        # in the above loop.
        if output is None:
            return

        yield pwncat.modules.Status("writing report")

        with output as filp:

            with session.db as db:
                host = db.query(pwncat.db.Host).filter_by(id=session.host).first()

            filp.write(f"# {host.ip} - Enumeration Report\n\n")
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
