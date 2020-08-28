#!/usr/bin/env python3
from io import IOBase
from pathlib import Path
import inspect

from rich.progress import Progress
from rich import markup

import pwncat.modules
from pwncat import util
from pwncat.util import console
from pwncat.modules.enumerate import EnumerateModule


def strip_markup(styled_text: str) -> str:
    text = markup.render(styled_text)
    return text.plain


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
    """ Perform multiple enumeration modules and write a formatted
    report to the filesystem. """

    ARGUMENTS = {
        "output": pwncat.modules.Argument(FileType("w"), default=None),
        "modules": pwncat.modules.Argument(pwncat.modules.List(str), default=[".*"]),
        "types": pwncat.modules.Argument(pwncat.modules.List(str), default=[]),
    }

    def run(self, output, modules, types):
        """ Perform a enumeration of the given moduels and save the output """

        module_names = modules

        # Find all the matching modules (use set to ensure uniqueness)
        modules = set()
        for name in module_names:
            modules = modules | set(pwncat.modules.match(f"enumerate.{name}"))

        # Enumerate all facts
        facts = {}
        with Progress(
            "collecting results",
            "•",
            "[blue]{task.fields[module]}",
            "•",
            "[cyan]{task.fields[status]}",
            transient=True,
            console=console,
        ) as progress:
            task = progress.add_task("", status="...", module="initializing")

            for module in modules:
                if not isinstance(module, EnumerateModule):
                    continue
                progress.update(task, module=module.name)

                result_object = module.run(types=types)

                if inspect.isgenerator(result_object):
                    for item in result_object:
                        progress.update(task, status=str(item))
                        if (
                            not isinstance(item, pwncat.modules.Status)
                            and item.type != "marker"
                        ):
                            if item.type not in facts:
                                facts[item.type] = [item]
                            else:
                                facts[item.type].append(item)
                else:
                    if isinstance(result_object, pwncat.db.Fact):
                        if result_object.type not in facts:
                            facts[result_object.type] = [result_object]
                        else:
                            facts[result_object.type].append(result_object)

        if output is None:
            for key in facts:
                yield from facts[key]
            return

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
