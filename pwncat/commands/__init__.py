#!/usr/bin/env python3
import traceback
from typing import TextIO, Type
from prompt_toolkit import PromptSession, ANSI
from prompt_toolkit.shortcuts import ProgressBar, confirm
from prompt_toolkit.completion import (
    Completer,
    PathCompleter,
    Completion,
    CompleteEvent,
    NestedCompleter,
    WordCompleter,
    merge_completers,
)
from pygments.lexer import RegexLexer, bygroups, include
from pygments.token import *
from pygments.style import Style
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from prompt_toolkit.styles import merge_styles, Style
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.document import Document
from prompt_toolkit.application.current import get_app
from prompt_toolkit.key_binding import KeyBindings
from pygments.styles import get_style_by_name
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory, History
from typing import Dict, Any, List, Iterable
from colorama import Fore
from enum import Enum, auto
from io import TextIOWrapper
import rich.text
import argparse
import pkgutil
import shlex
import sys
import fcntl
import termios
import tty
import os
import re

from pprint import pprint

import pwncat
import pwncat.db
from pwncat.commands.base import CommandDefinition, Complete
from pwncat.util import State, console
from pwncat.channel import ChannelClosed


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
        raise ValueError(f"mismatched braces")
    if inside_quotes:
        raise ValueError("missing ending quote")

    return "".join(result).split("\n")


class DatabaseHistory(History):
    """ Yield history from the host entry in the database """

    # NOTE - This is nerfed because of ZODB changes...
    def __init__(self, manager):
        super().__init__()
        self.manager = manager

    def load_history_strings(self) -> Iterable[str]:
        """ Load the history from the database """

        if False:
            with self.manager.new_db_session() as session:
                for history in (
                    session.query(pwncat.db.History)
                    .order_by(pwncat.db.History.id.desc())
                    .all()
                ):
                    yield history.command

    def store_string(self, string: str) -> None:
        """ Store a command in the database """

        if False:
            history = pwncat.db.History(command=string)

            with self.manager.new_db_session() as session:
                session.add(history)


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

        if self.prompt is None:
            self.setup_prompt()

        try:
            line = self.prompt.prompt().strip()
            self.dispatch_line(line)
        except (EOFError, OSError, KeyboardInterrupt, pwncat.manager.InteractiveExit):
            return

    def run(self):

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

    tokens = {}

    @classmethod
    def build(cls, commands: List["CommandDefinition"]) -> Type["CommandLexer"]:
        """ Build the RegexLexer token list from the command definitions """

        root = []
        for command in commands:
            root.append(("^" + re.escape(command.PROG), Name.Function, command.PROG))
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
                mode.append((r"\s+(\-\-help|\-h)", Name.Label))
            mode.append((r"\"", String, "string"))
            mode.append((r".", Text))
            cls.tokens[command.PROG] = mode

        root.append((r".", Text))
        cls.tokens["root"] = root
        cls.tokens["param"] = [
            (r"\"", String, "string"),
            (r"\s", Text, "#pop"),
            (r"[^\s]", Text),
        ]
        cls.tokens["string"] = [
            (r"[^\"\\]+", String),
            (r"\\.", String.Escape),
            ('"', String, "#pop"),
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
    """ Complete local file names/paths """

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
    """ Complete commands from a given list of commands """

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


# Here, we allocate the global parser object and initialize in-memory
# settings
parser = None
# parser: CommandParser = CommandParser()
# parser.setup_prompt()
