#!/usr/bin/env python3
import textwrap

import pwncat
import pwncat.modules
from pwncat.util import console
from pwncat.commands.base import CommandDefinition, Complete, Parameter


class Command(CommandDefinition):
    """
    Run a module. If no module is specified, use the module in the
    current context. You can enter a module context with the `use`
    command.

    Module arguments can be appended to the run command with `variable=value`
    syntax. Arguments are type-checked prior to executing, and the results
    are displayed to the terminal.

    To locate available modules, you can use the `search` command. To
    find documentation on individual modules including expected
    arguments, you can use the `info` command.
    """

    def get_module_choices(self):
        yield from [module.name for module in pwncat.modules.match("*")]

    PROG = "run"
    ARGS = {
        "--raw,-r": Parameter(
            Complete.NONE, action="store_true", help="Display raw results unformatted"
        ),
        "--traceback,-t": Parameter(
            Complete.NONE, action="store_true", help="Show traceback for module errors"
        )
        "module": Parameter(
            Complete.CHOICES,
            nargs="?",
            metavar="MODULE",
            choices=get_module_choices,
            help="The module name to execute",
        ),
        "args": Parameter(Complete.NONE, nargs="*", help="Module arguments"),
    }

    def run(self, args):

        if args.module is None and pwncat.victim.config.module is None:
            console.log("[red]error[/red]: no module specified")
            return
        elif args.module is None:
            args.module = pwncat.victim.config.module.name

        # Parse key=value pairs
        values = {}
        for arg in args.args:
            if "=" not in arg:
                values[arg] = True
            else:
                name, value = arg.split("=")
                values[name] = value

        # pwncat.victim.config.locals.update(values)
        config_values = pwncat.victim.config.locals.copy()
        config_values.update(values)

        try:
            result = pwncat.modules.run(args.module, **config_values)
            pwncat.victim.config.back()
        except pwncat.modules.ModuleFailed as exc:
            if args.traceback:
                console.print_exception()
            else:
                console.log(f"[red]error[/red]: module failed: {exc}")
            return
        except pwncat.modules.ModuleNotFound:
            console.log(f"[red]error[/red]: {args.module}: not found")
            return
        except pwncat.modules.ArgumentFormatError as exc:
            console.log(f"[red]error[/red]: {exc}: invalid argument")
            return
        except pwncat.modules.MissingArgument as exc:
            console.log(f"[red]error[/red]: missing argument: {exc}")
            return
        except pwncat.modules.InvalidArgument as exc:
            console.log(f"[red]error[/red]: invalid argument: {exc}")
            return

        if args.raw:
            console.print(result)
        else:

            if result is None or (isinstance(result, list) and not result):
                console.log(f"Module [bold]{args.module}[/bold] completed successfully")
                return

            if not isinstance(result, list):
                result = [result]
            self.display_item(title=args.module, results=result)

    def display_item(self, title, results):
        """ Display a possibly complex item """

        console.print(f"[bold underline]Module '{title}' Results[/bold underline]")

        # Uncategorized or raw results
        categories = {}
        uncategorized = []
        longform = []

        # Organize results by category
        for result in results:
            if isinstance(result, pwncat.modules.Result) and result.is_long_form():
                longform.append(result)
            elif (
                not isinstance(result, pwncat.modules.Result) or result.category is None
            ):
                uncategorized.append(result)
            elif result.category not in categories:
                categories[result.category] = [result]
            else:
                categories[result.category].append(result)

        # Show uncategorized results first
        if uncategorized:
            console.print(f"[bold]Uncategorized Results[/bold]")
            for result in uncategorized:
                console.print("- " + str(result))

        # Show all other categories
        if categories:
            for category, results in categories.items():
                console.print(f"[bold]{category}[/bold]")
                for result in results:
                    console.print("  - " + str(result))

        # Show long-form results in their own sections
        if longform:
            for result in longform:
                if result.category is None:
                    console.print(f"[bold]{result.title}[/bold]")
                else:
                    console.print(f"[bold]{result.category} - {result.title}[/bold]")
                console.print(textwrap.indent(result.description, "  "))
