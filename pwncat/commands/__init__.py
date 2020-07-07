#!/usr/bin/env python3
import traceback
from typing import TextIO, Type
from prompt_toolkit import PromptSession, ANSI
from prompt_toolkit.shortcuts import ProgressBar
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
from prompt_toolkit.lexers import PygmentsLexer
from prompt_toolkit.document import Document
from pygments.styles import get_style_by_name
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory, History
from typing import Dict, Any, List, Iterable
from colorama import Fore
from enum import Enum, auto
import argparse
import pkgutil
import shlex
import os
import re

from pprint import pprint

import pwncat
import pwncat.db
from pwncat.commands.base import CommandDefinition, Complete
from pwncat.util import State, console


def resolve_blocks(source: str):
    """ This is a dumb lexer that turns strings of text with code blocks (squigly
    braces) into a single long string separated by semicolons. All code blocks are
    converted to strings recursively with correct escaping levels. The resulting
    string can be sent to break_commands to iterate over the commands. """

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

    def load_history_strings(self) -> Iterable[str]:
        """ Load the history from the database """
        for history in (
            pwncat.victim.session.query(pwncat.db.History)
            .order_by(pwncat.db.History.id.desc())
            .all()
        ):
            yield history.command

    def store_string(self, string: str) -> None:
        """ Store a command in the database """
        history = pwncat.db.History(host_id=pwncat.victim.host.id, command=string)
        pwncat.victim.session.add(history)


class CommandParser:
    """ Handles dynamically loading command classes, parsing input, and
    dispatching commands. """

    def __init__(self):
        """ We need to dynamically load commands from pwncat.commands """

        self.commands: List["CommandDefinition"] = []

        for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
            if module_name == "base":
                continue
            self.commands.append(
                loader.find_module(module_name).load_module(module_name).Command()
            )

        self.prompt: PromptSession = None
        self.toolbar: PromptSession = None
        self.loading_complete = False
        self.aliases: Dict[str, CommandDefinition] = {}
        self.shortcuts: Dict[str, CommandDefinition] = {}

    def setup_prompt(self):
        """ This needs to happen after __init__ when the database is fully
        initialized. """

        if pwncat.victim is not None and pwncat.victim.host is not None:
            history = DatabaseHistory()
        else:
            history = InMemoryHistory()

        completer = CommandCompleter(self.commands)
        lexer = PygmentsLexer(CommandLexer.build(self.commands))
        style = style_from_pygments_cls(get_style_by_name("monokai"))
        auto_suggest = AutoSuggestFromHistory()

        self.prompt = PromptSession(
            [
                ("fg:ansiyellow bold", "(local) "),
                ("fg:ansimagenta bold", "pwncat"),
                ("", "$ "),
            ],
            completer=completer,
            lexer=lexer,
            style=style,
            auto_suggest=auto_suggest,
            complete_while_typing=False,
            history=history,
        )

    @property
    def loaded(self):
        return self.loading_complete

    @loaded.setter
    def loaded(self, value: bool):
        assert value == True
        self.loading_complete = True
        self.eval(pwncat.victim.config["on_load"], "on_load")

    def eval(self, source: str, name: str = "<script>"):
        """ Evaluate the given source file. This will execute the given string
        as a script of commands. Syntax is the same except that commands may
        be separated by semicolons, comments are accepted as following a "#" and
        multiline strings are supported with '"{' and '}"' as delimeters. """

        in_multiline_string = False
        lineno = 1

        for command in resolve_blocks(source):
            try:
                self.dispatch_line(command)
            except Exception as exc:
                console.log(
                    f"[red]error[/red]: [cyan]{name}[/cyan]: [yellow]{command}[/yellow]: {str(exc)}"
                )
                break

    def run_single(self):

        try:
            line = self.prompt.prompt().strip()
        except (EOFError, OSError, KeyboardInterrupt):
            pass
        else:
            if line != "":
                self.dispatch_line(line)

    def run(self):

        self.running = True

        while self.running:
            try:
                line = self.prompt.prompt().strip()

                if line == "":
                    continue

                self.dispatch_line(line)
            # We used to catch only KeyboardException, but this prevents a
            # badly written command from completely killing our remote
            # connection.
            except EOFError:
                # We don't have a connection yet, just exit
                if pwncat.victim is None or pwncat.victim.client is None:
                    break
                # We have a connection! Go back to raw mode
                pwncat.victim.state = State.RAW
                self.running = False
            except (Exception, KeyboardInterrupt):
                console.print_exception(width=None)
                continue

    #             except KeyboardInterrupt:
    #                 console.log("Keyboard Interrupt")
    #                 continue

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
            console.log(f"[red]error[/red]: {e.args[0]}")
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
                    console.log(f"[red]error[/red]: {argv[0]}: unknown command")
                    return

            if not self.loading_complete and not command.LOCAL:
                console.log(
                    f"[red]error[/red]: {argv[0]}: non-local command use before connection"
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
            command.run(args)

            if prog_name:
                command.parser.prog = prog_name

        except SystemExit:
            # The arguments were incorrect
            return


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

    def get_completions(self, document: Document, complete_event: CompleteEvent):

        before = document.text_before_cursor.split()[-1]
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        pipe = pwncat.victim.subprocess(
            f"ls -1 -a --color=never {shlex.quote(path)}", "r"
        )

        for name in pipe:
            name = name.decode("utf-8").strip()
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

    def __init__(self, commands: List["CommandDefinition"]):
        """ Construct a new command completer """

        self.layers = {}
        local_file_completer = LocalPathCompleter()
        remote_file_completer = RemotePathCompleter()

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

        if isinstance(this_completer, tuple) and this_completer[0] == "choices":
            this_completer = WordCompleter(this_completer[1])
        if isinstance(next_completer, tuple) and next_completer[0] == "choices":
            next_completer = WordCompleter(next_completer[1])

        if text.endswith(" "):
            yield from next_completer.get_completions(document, complete_event)
        else:
            yield from this_completer.get_completions(document, complete_event)
