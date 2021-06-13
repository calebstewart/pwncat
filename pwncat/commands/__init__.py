"""
This module implements the command parser, lexer, highlighter, etc for pwncat.
Each command is defined as an individual module under ``pwncat/commands`` which
defines a ``Command`` class that inherits from :class:`pwncat.commands.CommandDefinition`.

Each command is capable of specifying the expected arguments similar to the way
they specified with argparse. Internally, we use the :class:`Parameter` definitions
to build an ``argparse`` parser. We also use them to build a lexer capable of
automatic syntax highlighting at the prompt.

To define a new command, simple create a new module under ``pwncat/commands`` and
define a class named ``Command``.

Example Custom Command
----------------------

.. code-block:: python
    :caption: A Custom Command Placed in ``pwncat/commands``

    class Command(CommandDefinition):
        \""" Command documentation placed in the docstring \"""

        PROG = "custom"
        ARGS = {
            "--option,-o": Parameter(Complete.NONE, help="help info", action="store_true"),
            "positional": Parameter(
                Complete.CHOICES,
                metavar="POSITIONAL",
                choices=["hello", "world"],
                help="help information",
            ),
        }

        def run(self, manager: "pwncat.manager.Manager", args: "argparse.Namespace"):
            manager.log("we ran a custom command!")
"""
import os
import re
import sys
import tty
import fcntl
import shlex
import pkgutil
import termios
import argparse
from io import TextIOWrapper
from enum import Enum, auto
from typing import Dict, List, Type, Callable, Iterable
from functools import partial

import rich.text
from pygments import token
from prompt_toolkit import ANSI, PromptSession
from pygments.lexer import RegexLexer
from pygments.styles import get_style_by_name
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.styles import Style, merge_styles
from prompt_toolkit.history import History
from prompt_toolkit.document import Document
from prompt_toolkit.completion import (
    Completer,
    Completion,
    CompleteEvent,
    WordCompleter,
    merge_completers,
)
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from prompt_toolkit.application.current import get_app

import pwncat
import pwncat.db
from pwncat.util import console
from pwncat.channel import ChannelClosed


class Complete(Enum):
    """
    Command argument completion options. This defines how tab completion
    works for an individual command parameter/argument. If you choose to
    use the ``CHOICES`` type, you must specify the argparse ``choices``
    argument to the :class:`Parameter` constructor. This argument can
    either be an iterable or a callable which returns a generator. The
    callable takes as an argument the manager. This allows you to have
    contextual tab completions if needed.
    """

    CHOICES = auto()
    """ Complete argument from the list of choices specified in ``choices`` parameter """
    LOCAL_FILE = auto()
    """ Complete argument as a local file path """
    REMOTE_FILE = auto()
    """ Complete argument as a remote file path """
    NONE = auto()
    """ Do not provide argument completions """


class StoreConstOnce(argparse.Action):
    """Only allow the user to store a value in the destination once. This prevents
    users from selection multiple actions in the privesc parser."""

    def __call__(self, parser, namespace, values, option_string=None):
        if hasattr(self, "__" + self.dest + "_seen"):
            raise argparse.ArgumentError(self, "only one action may be specified")
        setattr(namespace, "__" + self.dest + "_seen", True)
        setattr(namespace, self.dest, self.const)


def StoreForAction(action: List[str]) -> Callable:
    """Generates a custom argparse Action subclass which verifies that the current
    selected "action" option is one of the provided actions in this function. If
    not, an error is raised."""

    class StoreFor(argparse.Action):
        """Store the value if the currently selected action matches the list of
        actions passed to this function."""

        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, "action", None) not in action:
                raise argparse.ArgumentError(
                    self,
                    f"{option_string}: only valid for {action}",
                )

            setattr(namespace, self.dest, values)

    return StoreFor


def StoreConstForAction(action: List[str]) -> Callable:
    """Generates a custom argparse Action subclass which verifies that the current
    selected "action" option is one of the provided actions in this function. If
    not, an error is raised. This stores the constant `const` to the `dest` argument.
    This is comparable to `store_const`, but checks that you have selected one of
    the specified actions."""

    class StoreFor(argparse.Action):
        """Store the value if the currently selected action matches the list of
        actions passed to this function."""

        def __call__(self, parser, namespace, values, option_string=None):
            if getattr(namespace, "action", None) not in action:
                raise argparse.ArgumentError(
                    self,
                    f"{option_string}: only valid for {action}",
                )

            setattr(namespace, self.dest, self.const)

    return StoreFor


def get_module_choices(command):
    """Yields a list of module choices to be used with command argument
    choices to select a valid module for the current target. For example
    you could use ``Parameter(Complete.CHOICES, choices=get_module_choices)``"""

    if command.manager.target is None:
        return

    yield from [
        module.name.removeprefix("agnostic.").removeprefix(
            command.manager.target.platform.name + "."
        )
        for module in command.manager.target.find_module("*")
    ]


class Parameter:
    """Generic parameter definition for commands.

    This class allows you to specify the syntax highlighting, tab completion
    and argparse settings for a command parameter in on go. The ``complete``
    argument tells pwncat how to tab complete your argument. The ``token``
    argument is normally ommitted but can be used to change the pygments
    syntax highlighting for your argument. All other arguments are passed
    directly to ``argparse`` when constructing the parser.

    :param complete: the completion type
    :type complete: Complete
    :param token: the Pygments token to highlight this argument with
    :type token: Pygments Token
    :param group: true for a group definition, a string naming the group to be a part of, or none
    :param mutex: for group definitions, indicates whether this is a mutually exclusive group
    :param args: positional arguments for ``add_argument`` or ``add_argument_group``
    :param kwargs: keyword arguments for ``add_argument`` or ``add_argument_group``
    """

    def __init__(
        self,
        complete: Complete,
        token=token.Name.Label,
        group: str = None,
        *args,
        **kwargs,
    ):
        self.complete = complete
        self.token = token
        self.group = group
        self.args = args
        self.kwargs = kwargs


class Group:
    """
    This just wraps the parameters to the add_argument_group and add_mutually_exclusive_group
    """

    def __init__(self, mutex: bool = False, **kwargs):
        self.mutex = mutex
        self.kwargs = kwargs


class CommandDefinition:
    """
    Generic structure for a local command.

    The docstring for your command class becomes the long-form help for your command.
    See the above example for a complete custom command definition.

    :param manager: the controlling manager for this command
    :type manager: pwncat.manager.Manager
    """

    PROG = "unimplemented"
    """ The name of your new command """
    ARGS: Dict[str, Parameter] = {}
    """ A dictionary of parameter definitions created with the ``Parameter`` class.
    If this is None, your command will receive the raw argument string and no processing
    will be done except removing the leading command name.
    """
    GROUPS: Dict[str, Group] = {}
    """ A dictionary mapping group definitions to group names. The parameters to Group
    are passed directly to either add_argument_group or add_mutually_exclusive_group
    with the exception of the mutex arg, which determines the group type. """
    DEFAULTS = {}
    """ A dictionary of default values (passed directly to ``ArgumentParser.set_defaults``) """
    LOCAL = False
    """ Whether this command is purely local or requires an connected remote host """

    # An example definition of arguments
    # PROG = "command"
    # ARGS = {
    #     "--all,-a": parameter(
    #         Complete.NONE, action="store_true", help="A switch/option"
    #     ),
    #     "--file,-f": parameter(Complete.LOCAL_FILE, help="A local file"),
    #     "--rfile": parameter(Complete.REMOTE_FILE, help="A remote file"),
    #     "positional": parameter(
    #         Complete.CHOICES, choices=["a", "b", "c"], help="Choose one!"
    #     ),
    # }

    def __init__(self, manager: "pwncat.manager.Manager"):
        """Initialize a new command instance. Parse the local arguments array
        into an argparse object."""

        self.manager = manager

        # Create the parser object
        if self.ARGS is not None:
            self.parser = argparse.ArgumentParser(
                prog=self.PROG,
                description=self.__doc__,
                formatter_class=argparse.RawDescriptionHelpFormatter,
            )
            self.build_parser(self.parser, self.ARGS, self.GROUPS)
        else:
            self.parser = None

    def run(self, manager: "pwncat.manager.Manager", args):
        """
        This is the "main" for your new command. This should perform the action
        represented by your command.

        :param manager: the manager to operate on
        :type manager: pwncat.manager.Manager
        :param args: the argparse Namespace containing your parsed arguments
        """
        raise NotImplementedError

    def build_parser(
        self,
        parser: argparse.ArgumentParser,
        args: Dict[str, Parameter],
        group_defs: Dict[str, Group],
    ):
        """
        Parse the ARGS and DEFAULTS dictionaries to build an argparse ArgumentParser
        for this command. You should not need to overload this.

        :param parser: the parser object to add arguments to
        :param args: the ARGS dictionary
        """

        groups = {}
        for name, definition in group_defs.items():
            if definition.mutex:
                groups[name] = parser.add_mutually_exclusive_group(**definition.kwargs)
            else:
                groups[name] = parser.add_argument_group(**definition.kwargs)

        for arg, param in args.items():
            names = arg.split(",")

            if param.group is not None and param.group not in groups:
                raise ValueError(f"{param.group}: no such group")

            if param.group is not None:
                group = groups[param.group]
            else:
                group = parser

            # Patch choice to work with a callable
            if "choices" in param.kwargs and callable(param.kwargs["choices"]):
                method = param.kwargs["choices"]

                class wrapper:
                    def __init__(wself, method):
                        wself.method = method

                    def __iter__(wself):
                        yield from wself.method(self)

                param.kwargs["choices"] = wrapper(method)

            # Patch "type" so we can see "self"
            if (
                "type" in param.kwargs
                and isinstance(param.kwargs["type"], tuple)
                and param.kwargs["type"][0] == "method"
            ):
                param.kwargs["type"] = partial(param.kwargs["type"][1], self)

            group.add_argument(*names, *param.args, **param.kwargs)

        parser.set_defaults(**self.DEFAULTS)


def resolve_blocks(source: str):
    """This is a dumb lexer that turns strings of text with code blocks (squigly
    braces) into a single long string separated by semicolons. All code blocks are
    converted to strings recursively with correct escaping levels. The resulting
    string can be sent to break_commands to iterate over the commands."""

    result = []
    in_brace = False
    inside_quotes = False
    i = 0
    lineno = 1

    while i < len(source):
        if not inside_quotes:
            if source[i] == '"':
                inside_quotes = True
                result.append("\\" * int(in_brace) + '"')
            elif source[i] == "{" and not in_brace:
                result.append('"')
                in_brace = True
            elif source[i] == "}":
                if not in_brace:
                    raise ValueError(f"line {lineno}: mismatched closing brace")
                in_brace = False
                result.append('"')
            elif source[i] == "\\":
                result.append("\\" * (int(in_brace)))
            elif source[i] == "\n" and in_brace:
                result.append("\\n")
            elif source[i] == "#":
                # Comment
                while i < len(source) and source[i] != "\n":
                    i += 1
            else:
                result.append(source[i])
        else:
            if source[i] == '"':
                inside_quotes = False
                result.append("\\" * int(in_brace) + '"')
            elif source[i] == "\\":
                result.append("\\" * (in_brace + 1))
            elif source[i] == "\n":
                raise ValueError(f"line {lineno}: newlines cannot appear in strings")
            else:
                result.append(source[i])
        if source[i] == "\n":
            lineno += 1
        i += 1

    if in_brace:
        raise ValueError("mismatched braces")
    if inside_quotes:
        raise ValueError("missing ending quote")

    return "".join(result).split("\n")


class DatabaseHistory(History):
    """ Yield history from the host entry in the database """

    def __init__(self, manager):
        super().__init__()
        self.manager = manager

    def load_history_strings(self) -> Iterable[str]:
        """ Load the history from the database """

        with self.manager.db.transaction() as conn:
            yield from reversed(conn.root.history)

    def store_string(self, string: str) -> None:
        """ Store a command in the database """

        with self.manager.db.transaction() as conn:
            conn.root.history.append(string)


class CommandParser:
    """Handles dynamically loading command classes, parsing input, and
    dispatching commands. This class effectively has complete control over
    the terminal whenever in an interactive pwncat session. It will change
    termios modes for the control tty at will in order to support raw vs
    command mode."""

    def __init__(self, manager: "pwncat.manager.Manager"):
        """ We need to dynamically load commands from pwncat.commands """

        self.manager = manager
        self.commands: List["CommandDefinition"] = []

        for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
            if module_name == "base":
                continue
            self.commands.append(
                loader.find_module(module_name)
                .load_module(module_name)
                .Command(manager)
            )

        self.prompt: PromptSession = None
        self.toolbar: PromptSession = None
        self.loading_complete = False
        self.aliases: Dict[str, CommandDefinition] = {}
        self.shortcuts: Dict[str, CommandDefinition] = {}
        self.found_prefix: bool = False
        # Saved terminal state to support switching between raw and normal
        # mode.
        self.saved_term_state = None

    def setup_prompt(self):
        """This needs to happen after __init__ when the database is fully
        initialized."""

        history = DatabaseHistory(self.manager)
        completer = CommandCompleter(self.manager, self.commands)
        lexer = PygmentsLexer(CommandLexer.build(self.commands))
        style = style_from_pygments_cls(get_style_by_name("monokai"))
        auto_suggest = AutoSuggestFromHistory()
        bindings = KeyBindings()

        @bindings.add("c-q")
        def _(event):
            """ Exit interactive mode """

            get_app().exit(exception=pwncat.manager.InteractiveExit())

        self.prompt = PromptSession(
            [
                ("fg:ansiyellow bold", "(local) "),
                ("fg:ansimagenta bold", "pwncat"),
                ("", "$ "),
            ],
            completer=completer,
            lexer=lexer,
            style=merge_styles(
                [style, Style.from_dict({"bottom-toolbar": "#333333 bg:#ffffff"})]
            ),
            auto_suggest=auto_suggest,
            complete_while_typing=False,
            history=history,
            bottom_toolbar=self._render_toolbar,
            key_bindings=bindings,
        )

    def _render_toolbar(self):
        """ Render the formatted text for the bottom toolbar """

        if self.manager.target is None:
            markup_result = "Active Session: [red]None[/red]"
        else:
            markup_result = f"Active Session: {self.manager.target.platform}"

        # Convert rich-style markup to prompt_toolkit formatted text
        text = rich.text.Text.from_markup(markup_result)
        segments = list(text.render(console))
        rendered = []

        # Here we take each segment's stile, invert the color and render the
        # segment text. This is because the bottom toolbar has it's colors
        # inverted.
        for i in range(len(segments)):
            style = segments[i].style.copy()
            temp = style.color
            style._color = segments[i].style.bgcolor
            style._bgcolor = temp
            rendered.append(style.render(segments[i].text))

        # Join the rendered segments to ANSI escape sequences.
        # This format can be parsed by prompt_toolkit formatted text.
        ansi_result = "".join(rendered)

        # Produce prompt_toolkit formatted text from the ANSI escaped string
        return ANSI(ansi_result)

    def eval(self, source: str, name: str = "<script>"):
        """Evaluate the given source file. This will execute the given string
        as a script of commands. Syntax is the same except that commands may
        be separated by semicolons, comments are accepted as following a "#" and
        multiline strings are supported with '"{' and '}"' as delimeters."""

        for command in resolve_blocks(source):
            try:
                self.dispatch_line(command)
            except ChannelClosed as exc:
                # A channel was unexpectedly closed
                self.manager.log(f"[red]warning[/red]: {exc.channel}: channel closed")
                # Ensure any existing sessions are cleaned from the manager
                exc.cleanup(self.manager)
            except pwncat.manager.InteractiveExit:
                # Within a script, `exit` means to exit the script, not the
                # interpreter
                break
            except Exception as exc:
                console.log(
                    f"[red]error[/red]: [cyan]{name}[/cyan]: [yellow]{command}[/yellow]: {str(exc)}"
                )
                break

    def run_single(self):
        """ Execute one Read-Execute iteration. This will prompt the user for input.  """

        if self.prompt is None:
            self.setup_prompt()

        try:
            line = self.prompt.prompt().strip()
            self.dispatch_line(line)
        except (EOFError, OSError, KeyboardInterrupt, pwncat.manager.InteractiveExit):
            return

    def run(self):
        """Execute the pwncat REPL. This will continue running until an :class:`InteractiveExit`
        exception or a :class:`EOFError` exception are raised."""

        if self.prompt is None:
            self.setup_prompt()

        running = True

        while running:
            try:

                if self.manager.config.module:
                    self.prompt.message = [
                        (
                            "fg:ansiyellow bold",
                            f"({self.manager.config.module.name}) ",
                        ),
                        ("fg:ansimagenta bold", "pwncat"),
                        ("", "$ "),
                    ]
                else:
                    self.prompt.message = [
                        ("fg:ansiyellow bold", "(local) "),
                        ("fg:ansimagenta bold", "pwncat"),
                        ("", "$ "),
                    ]

                line = self.prompt.prompt().strip()

                if line == "":
                    continue

                self.dispatch_line(line)
            # We used to catch only KeyboardException, but this prevents a
            # badly written command from completely killing our remote
            # connection.
            except EOFError:
                # C-d was pressed. Assume we want to exit the prompt.
                running = False
            except KeyboardInterrupt:
                # Normal C-c from a shell just clears the current prompt
                continue
            except ChannelClosed as exc:
                # A channel was unexpectedly closed
                self.manager.log(f"[red]warning[/red]: {exc.channel}: channel closed")
                # Ensure any existing sessions are cleaned from the manager
                exc.cleanup(self.manager)
            except pwncat.manager.InteractiveExit:
                # We don't want this caught below, so we catch it here
                # then re-raise it to be caught by the interactive method
                raise
            except (Exception, KeyboardInterrupt):
                console.print_exception(width=None)
                continue

    def dispatch_line(self, line: str, prog_name: str = None):
        """ Parse the given line of command input and dispatch a command """

        # Account for blank or whitespace only lines
        line = line.strip()
        if line == "":
            return

        try:
            # Spit the line with shell rules
            argv = shlex.split(line)
        except ValueError as e:
            self.manager.log(f"[red]error[/red]: {e.args[0]}")
            return

        if argv[0][0] in self.shortcuts:
            command = self.shortcuts[argv[0][0]]
            argv[0] = argv[0][1:]
            args = argv
            line = line[1:]
        else:
            line = f"{argv[0]} ".join(line.split(f"{argv[0]} ")[1:])
            # Search for a matching command
            for command in self.commands:
                if command.PROG == argv[0]:
                    break
            else:
                if argv[0] in self.aliases:
                    command = self.aliases[argv[0]]
                else:
                    self.manager.log(f"[red]error[/red]: {argv[0]}: unknown command")
                    return

            if self.manager.target is None and not command.LOCAL:
                self.manager.log(
                    f"[red]error[/red]: {argv[0]}: active session required"
                )
                return

            args = argv[1:]

        args = [a.encode("utf-8").decode("unicode_escape") for a in args]

        try:
            if prog_name:
                temp_name = command.parser.prog
                command.parser.prog = prog_name
                prog_name = temp_name

            # Parse the arguments
            if command.parser:
                args = command.parser.parse_args(args)
            else:
                args = line

            # Run the command
            command.run(self.manager, args)

            if prog_name:
                command.parser.prog = prog_name

        except SystemExit:
            # The arguments were incorrect
            return

    def parse_prefix(self, channel, data: bytes):
        """Parse data received from the user when in pwncat's raw mode.
        This will intercept key presses from the user and interpret the
        prefix and any bound keyboard shortcuts. It also sends any data
        without a prefix to the remote channel.

        :param data: input data from user
        :type data: bytes
        """

        buffer = b""

        for c in data:
            if not self.found_prefix and c != pwncat.config["prefix"].value:
                buffer += c
                continue
            elif not self.found_prefix and c == pwncat.config["prefix"].value:
                self.found_prefix = True
                channel.send(buffer)
                buffer = b""
                continue
            elif self.found_prefix:
                try:
                    binding = pwncat.config.binding(c)
                    if binding.strip() == "pass":
                        buffer += c
                    else:
                        # Restore the normal terminal
                        self.restore_term()

                        # Run the binding script
                        self.eval(binding, "<binding>")

                        # Drain any channel output
                        channel.drain()
                        channel.send(b"\n")

                        # Go back to a raw terminal
                        self.raw_mode()
                except KeyError:
                    pass
                self.found_prefix = False

        # Flush any remaining raw data bound for the victim
        channel.send(buffer)

    def raw_mode(self):
        """Save the current terminal state and enter raw mode.
        If the terminal is already in raw mode, this function
        does nothing."""

        if self.saved_term_state is not None:
            return

        # Ensure we don't have any weird buffering issues
        sys.stdout.flush()

        # Python doesn't provide a way to use setvbuf, so we reopen stdout
        # and specify no buffering. Duplicating stdin allows the user to press C-d
        # at the local prompt, and still be able to return to the remote prompt.
        try:
            os.dup2(sys.stdin.fileno(), sys.stdout.fileno())
        except OSError:
            pass
        sys.stdout = TextIOWrapper(
            os.fdopen(os.dup(sys.stdin.fileno()), "bw", buffering=0),
            write_through=True,
            line_buffering=False,
        )

        # Grab and duplicate current attributes
        fild = sys.stdin.fileno()
        old = termios.tcgetattr(fild)
        new = termios.tcgetattr(fild)

        # Remove ECHO from lflag and ensure we won't block
        new[3] &= ~(termios.ECHO | termios.ICANON)
        new[6][termios.VMIN] = 0
        new[6][termios.VTIME] = 0
        termios.tcsetattr(fild, termios.TCSADRAIN, new)

        # Set raw mode
        tty.setraw(sys.stdin)

        orig_fl = fcntl.fcntl(sys.stdin, fcntl.F_GETFL)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFL, orig_fl)

        self.saved_term_state = old, orig_fl

    def restore_term(self, new_line=True):
        """Restores the normal terminal settings. This does nothing if the
        terminal is not currently in raw mode."""

        if self.saved_term_state is None:
            return

        termios.tcsetattr(
            sys.stdin.fileno(), termios.TCSADRAIN, self.saved_term_state[0]
        )
        # tty.setcbreak(sys.stdin)
        fcntl.fcntl(sys.stdin, fcntl.F_SETFL, self.saved_term_state[1])

        if new_line:
            sys.stdout.write("\n")

        self.saved_term_state = None


class CommandLexer(RegexLexer):
    """Implements a Regular Expression based pygments lexer for dynamically highlighting
    the pwncat prompt during typing. The tokens are generated from command definitions."""

    tokens = {}

    @classmethod
    def build(cls, commands: List["CommandDefinition"]) -> Type["CommandLexer"]:
        """ Build the RegexLexer token list from the command definitions """

        root = []
        for command in commands:
            root.append(
                ("^" + re.escape(command.PROG), token.Name.Function, command.PROG)
            )
            mode = []
            if command.ARGS is not None:
                for args, param in command.ARGS.items():
                    for arg in args.split(","):
                        if not arg.startswith("-"):
                            continue
                        if param.complete != Complete.NONE:
                            # Enter param state
                            mode.append((r"\s+" + re.escape(arg), param.token, "param"))
                        else:
                            # Don't enter param state
                            mode.append((r"\s+" + re.escape(arg), param.token))
                mode.append((r"\s+(\-\-help|\-h)", token.Name.Label))
            mode.append((r"\"", token.String, "string"))
            mode.append((r".", token.Text))
            cls.tokens[command.PROG] = mode

        root.append((r".", token.Text))
        cls.tokens["root"] = root
        cls.tokens["param"] = [
            (r"\"", token.String, "string"),
            (r"\s", token.Text, "#pop"),
            (r"[^\s]", token.Text),
        ]
        cls.tokens["string"] = [
            (r"[^\"\\]+", token.String),
            (r"\\.", token.String.Escape),
            ('"', token.String, "#pop"),
        ]

        return cls


class RemotePathCompleter(Completer):
    """ Complete remote file names/paths """

    def __init__(self, manager: "pwncat.manager.Manager", *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.manager = manager

    def get_completions(self, document: Document, complete_event: CompleteEvent):

        if self.manager.target is None:
            return

        before = document.text_before_cursor.split()[-1]
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        for name in self.manager.target.platform.listdir(path):
            if name.startswith(partial_name):
                yield Completion(
                    name,
                    start_position=-len(partial_name),
                    display=[("#ff0000", "(remote)"), ("", f" {name}")],
                )


class LocalPathCompleter(Completer):
    """ Complete local file names/paths. """

    def get_completions(self, document: Document, complete_event: CompleteEvent):

        before = document.text_before_cursor.split()[-1]
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        # Ensure the directory exists
        if not os.path.isdir(path):
            return

        for name in os.listdir(path):
            if name.startswith(partial_name):
                yield Completion(
                    name,
                    start_position=-len(partial_name),
                    display=[("fg:ansiyellow", "(local)"), ("", f" {name}")],
                )


class CommandCompleter(Completer):
    """Tab-complete commands and all of their arguments dynamically using the
    command definitions and their associated argument definitions."""

    def __init__(
        self, manager: "pwncat.manager.Manager", commands: List["CommandDefinition"]
    ):
        """ Construct a new command completer """

        self.layers = {}
        local_file_completer = LocalPathCompleter()
        remote_file_completer = RemotePathCompleter(manager)

        for command in commands:
            self.layers[command.PROG] = [None, [], {}]
            option_names = []
            if command.ARGS is not None:
                for name_list, param in command.ARGS.items():
                    name_list = name_list.split(",")
                    if param.complete == Complete.CHOICES:
                        completer = ("choices", param.kwargs["choices"])
                    elif param.complete == Complete.LOCAL_FILE:
                        completer = local_file_completer
                    elif param.complete == Complete.REMOTE_FILE:
                        completer = remote_file_completer
                    elif param.complete == Complete.NONE:
                        completer = None
                    if len(name_list) == 1 and not name_list[0].startswith("-"):
                        self.layers[command.PROG][1].append(completer)
                    else:
                        for name in name_list:
                            self.layers[command.PROG][2][name] = completer
                            option_names.append(name)
                self.layers[command.PROG][0] = WordCompleter(
                    option_names + ["--help", "-h"]
                )

        self.completer = WordCompleter(list(self.layers))

    def get_completions(
        self, document: Document, complete_event: CompleteEvent
    ) -> Iterable[Completion]:
        """ Get a list of completions for the given document """

        text = document.text_before_cursor.lstrip()
        try:
            args = shlex.split(text)
        except ValueError:
            try:
                args = shlex.split(text + '"')
            except ValueError:
                args = shlex.split(text + "'")

        # We haven't finished typing the command. Use our word completer for
        # commands
        if text == "" or (len(args) == 1 and not text.endswith(" ")):
            yield from self.completer.get_completions(document, complete_event)
            return

        # Not in a known command, can't autocomplete
        if args[0] not in self.layers:
            return

        command = self.layers[args[0]]
        args = args[1:]
        next_completer = command[0]
        this_completer = command[0]
        positional = 0
        # state = "options", completing options next
        # state = "arguments", completing arguments to options next
        state = "options"

        for arg in args:
            if state == "options":
                # Flag options
                if arg.startswith("-"):
                    # Exact match, with a sub-completer
                    if arg in command[2] and command[2][arg] is not None:
                        # Completer for next argument
                        next_completer = command[2][arg]
                        state = "arguments"
                    # Exact match, with no arguments
                    elif arg in command[2]:
                        # Command has no argument, next completer is options
                        # completer
                        next_completer = command[0]
                        state = "options"
                        this_completer = command[0]
                    # Non-exact match
                    else:
                        next_completer = command[0]
                        this_completer = command[0]
                        state = "options"
                # Appears to be a positional argument, grab next positional
                # completer and increment positional count
                else:
                    if positional < len(command[1]):
                        this_completer = command[1][positional]
                        next_completer = command[0]
                        state = "options"
                        positional += 1
                    else:
                        this_completer = command[0]
                        next_completer = command[0]
                        state = "options"
            else:
                # Completing an argument to a option/switch. We can't verify
                # it's legitimacy, so we assume it's right, and reset to a
                # default state.
                state = "options"
                this_completer = next_completer
                next_completer = command[0]

        # We are completing the first argument. This could be
        # any option argument or the first positional argument.
        # We need to merge them.
        if not args and text.endswith(" ") and command[1]:
            completer = command[1][0]
            if isinstance(completer, tuple) and completer[0] == "choices":
                completer = WordCompleter(completer[1], WORD=True)
            next_completer = merge_completers([next_completer, completer])

        if isinstance(this_completer, tuple) and this_completer[0] == "choices":
            this_completer = WordCompleter(this_completer[1], WORD=True)
        if isinstance(next_completer, tuple) and next_completer[0] == "choices":
            next_completer = WordCompleter(next_completer[1], WORD=True)

        if text.endswith(" ") and next_completer is not None:
            yield from next_completer.get_completions(document, complete_event)
        elif this_completer is not None:
            yield from this_completer.get_completions(document, complete_event)
