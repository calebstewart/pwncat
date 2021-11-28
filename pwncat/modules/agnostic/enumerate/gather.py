#!/usr/bin/env python3
import fnmatch
from io import IOBase

import pwncat.modules
from pwncat.modules import Status, ModuleFailed
from pwncat.modules.enumerate import EnumerateModule


def iterate_two_lists(a, b):
    yield from a
    yield from b


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
        "exclude": pwncat.modules.Argument(
            pwncat.modules.List(str),
            default=None,
            help="glob pattern of module names to exclude",
        ),
    }
    PLATFORM = None

    def run(self, session, output, modules, types, clear, cache, exclude):
        """Perform a enumeration of the given modules and save the output"""

        module_names = modules

        # Find all the matching modules (use set to ensure uniqueness)
        modules = set()
        for name in module_names:
            modules = modules | set(
                list(session.find_module(f"enumerate.{name}", base=EnumerateModule))
            )

        if exclude is not None and exclude:
            modules = (
                module
                for module in modules
                if not any(fnmatch.fnmatch(module.name, e) for e in exclude)
            )

        if clear:
            for module in modules:
                yield pwncat.modules.Status(module.name)
                module.run(session, clear=True)
            return

        # Enumerate all facts
        facts = {}

        if cache:
            for fact in iterate_two_lists(session.target.facts, session.facts):
                if not types or any(
                    any(fnmatch.fnmatch(t2, t1) for t2 in fact.types) for t1 in types
                ):
                    if fact.type not in facts:
                        facts[fact.type] = [fact]
                    else:
                        facts[fact.type].append(fact)

                    if output is None:
                        yield fact
                    else:
                        yield Status(fact.title(session))

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
                for item in module.run(session, types=types):
                    if item.type not in facts:
                        facts[item.type] = [item]
                        if output is None:
                            yield item
                        else:
                            yield Status(item.title(session))
                    else:
                        for fact in facts[item.type]:
                            if fact == item:
                                break
                        else:
                            facts[item.type].append(item)
                            if output is None:
                                yield item
                            else:
                                yield Status(item.title(session))
            except ModuleFailed as exc:
                session.log(f"[red]{module.name}[/red]: {str(exc)}")
