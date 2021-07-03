#!/usr/bin/env python3
import os
import datetime
from typing import List

import jinja2
from rich.markdown import Markdown

import pwncat
from pwncat.util import console, strip_markup
from pwncat.modules import Bool, Argument, BaseModule, ModuleFailed


class Module(BaseModule):
    """
    Run common enumerations and produce a report. Optionally, write the report
    in markdown format to a file.
    """

    PLATFORM = None
    ARGUMENTS = {
        "output": Argument(
            str,
            default="terminal",
            help="Path to markdown file to store report (default: render to terminal)",
        ),
        "template": Argument(
            str,
            default="platform name",
            help="The name of the template to use (default: platform name)",
        ),
        "fmt": Argument(
            str,
            default="md",
            help='The format of the output. This can be "md" or "html". (default: md)',
        ),
        "custom": Argument(
            Bool,
            default=False,
            help="Use a custom template; the template argument must be the path to a jinja2 template",
        ),
    }

    def generate_markdown_table(self, data: List[List], headers: bool = False):
        """Generate a markdown table from the given data and headers"""

        # Get column widths
        widths = [
            max(len(data[r][c]) for r in range(len(data))) for c in range(len(data[0]))
        ]

        rows = []
        for r in range(len(data)):
            rows.append(
                "|"
                + "|".join(
                    [
                        " " + data[r][c] + " " * (widths[c] - len(data[r][c]) + 1)
                        for c in range(len(data[r]))
                    ]
                )
                + "|"
            )

        if headers:
            rows.insert(
                1,
                "|"
                + "|".join([" " + "-" * widths[c] + " " for c in range(len(data[r]))])
                + "|",
            )

        return "  \n".join(rows)

    def run(self, session: "pwncat.manager.Session", output, template, fmt, custom):
        """Perform enumeration and optionally write report"""

        if custom:
            env = jinja2.Environment(
                loader=jinja2.FileSystemLoader(os.getcwd()),
                # autoescape=jinja2.select_autoescape(["md", "html"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )
        else:
            env = jinja2.Environment(
                loader=jinja2.PackageLoader("pwncat", "data/reports"),
                # autoescape=jinja2.select_autoescape(["md", "html"]),
                trim_blocks=True,
                lstrip_blocks=True,
            )

        if template == "platform name":
            use_platform = True
            template = session.platform.name
        else:
            use_platform = False

        env.filters["first_or_none"] = lambda thing: thing[0] if thing else None
        env.filters["attr_or"] = (
            lambda fact, name, default=None: getattr(fact, name)
            if fact is not None
            else default
        )
        env.filters["title_or_unknown"] = (
            lambda fact: strip_markup(fact.title(session))
            if fact is not None
            else "unknown"
        )
        env.filters["remove_rich"] = lambda thing: strip_markup(str(thing))
        env.filters["table"] = self.generate_markdown_table

        try:
            template = env.get_template(f"{template}.{fmt}")
        except jinja2.TemplateNotFound as exc:
            if use_platform:
                try:
                    template = env.get_template(f"generic.{fmt}")
                except jinja2.TemplateNotFound as exc:
                    raise ModuleFailed(str(exc)) from exc
            else:
                raise ModuleFailed(str(exc)) from exc

        # Just some convenience things for the templates
        context = {
            "target": session.target,
            "manager": session.manager,
            "session": session,
            "platform": session.platform,
            "datetime": datetime.datetime.now(),
        }

        try:
            if output != "terminal":
                with open(output, "w") as filp:
                    template.stream(context).dump(filp)
            else:
                markdown = Markdown(template.render(context), hyperlinks=False)
                console.print(markdown)
        except jinja2.TemplateError as exc:
            raise ModuleFailed(str(exc)) from exc
