#!/usr/bin/env python3
import textwrap

import pwncat
import pwncat.modules
from pwncat.util import console
from pwncat.commands import (
    Complete,
    Parameter,
    CommandDefinition,
    get_module_choices,
)


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

    PROG = "run"
    ARGS = {
        "--raw,-r": Parameter(
            Complete.NONE, action="store_true", help="Display raw results unformatted"
        ),
        "--traceback,-t": Parameter(
            Complete.NONE, action="store_true", help="Show traceback for module errors"
        ),
        "module": Parameter(
            Complete.CHOICES,
            nargs="?",
            metavar="MODULE",
            choices=get_module_choices,
            help="The module name to execute",
        ),
        "args": Parameter(Complete.NONE, nargs="*", help="Module arguments"),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        module_name = args.module

        if args.module is None and manager.config.module is None:
            console.log("[red]error[/red]: no module specified")
            return
        elif args.module is None:
            module_name = manager.config.module.name

        # Parse key=value pairs
        values = {}
        for arg in args.args:
            if "=" not in arg:
                values[arg] = True
            else:
                name, value = arg.split("=")
                values[name] = value

        # pwncat.config.locals.update(values)
        config_values = manager.config.locals.copy()
        config_values.update(values)

        try:
            result = manager.target.run(module_name, **config_values)

            if args.module is not None:
                manager.config.back()
        except pwncat.modules.ModuleFailed as exc:
            if args.traceback:
                console.print_exception()
            else:
                console.log(f"[red]error[/red]: module failed: {exc}")
            return
        except pwncat.modules.ModuleNotFound:
            console.log(f"[red]error[/red]: {module_name}: not found")
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
                console.log(f"Module [bold]{module_name}[/bold] completed successfully")
                return

            if not isinstance(result, list):
                result = [result]
            self.display_item(manager, title=module_name, results=result)

    def display_item(self, manager, title, results):
        """Display a possibly complex item"""

        console.print(f"[bold underline]Module '{title}' Results[/bold underline]")

        # Uncategorized or raw results
        categories = {}
        uncategorized = []
        longform = []

        # Organize results by category
        for result in results:
            if isinstance(result, pwncat.modules.Result) and result.is_long_form(
                manager.target
            ):
                longform.append(result)
            elif (
                not isinstance(result, pwncat.modules.Result)
                or result.category(manager.target) is None
            ):
                uncategorized.append(result)
            elif result.category(manager.target) not in categories:
                categories[result.category(manager.target)] = [result]
            else:
                categories[result.category(manager.target)].append(result)

        # Show uncategorized results first
        if uncategorized:
            console.print(f"[bold]Uncategorized Results[/bold]")
            for result in uncategorized:
                console.print("- " + result.title(manager.target))

        # Show all other categories
        if categories:
            for category, results in categories.items():
                console.print(f"[bold]{category}[/bold]")
                for result in results:
                    console.print(f"  - {result.title(manager.target)}")

        # Show long-form results in their own sections
        if longform:
            for result in longform:
                if result.category(manager.target) is None:
                    console.print(f"[bold]{result.title(manager.target)}[/bold]")
                else:
                    console.print(
                        f"[bold]{result.category(manager.target)} - {result.title(manager.target)}[/bold]"
                    )
                console.print(textwrap.indent(result.description(manager.target), "  "))
