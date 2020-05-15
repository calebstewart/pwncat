#!/usr/bin/env python3
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
from prompt_toolkit.history import InMemoryHistory
from typing import Dict, Any, List, Iterable
from enum import Enum, auto
import argparse
import pkgutil
import shlex
import os
import re

from pprint import pprint

from pwncat.commands.base import CommandDefinition, Complete
from pwncat.util import State
from pwncat import util


class CommandParser:
    """ Handles dynamically loading command classes, parsing input, and
    dispatching commands. """

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        """ We need to dynamically load commands from pwncat.commands """

        self.commands: List["CommandDefinition"] = []

        for loader, module_name, is_pkg in pkgutil.walk_packages(__path__):
            if module_name == "base":
                continue
            self.commands.append(
                loader.find_module(module_name)
                .load_module(module_name)
                .Command(pty, self)
            )

        history = InMemoryHistory()
        completer = CommandCompleter(pty, self.commands)
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
        self.toolbar = PromptSession(
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
            prompt_in_toolbar=True,
            history=history,
        )

        self.pty = pty

    def run_single(self):

        try:
            line = self.toolbar.prompt().strip()
        except (EOFError, OSError, KeyboardInterrupt):
            pass
        else:
            if line != "":
                self.dispatch_line(line)

    def run(self):

        self.running = True

        while self.running:
            try:
                try:
                    line = self.prompt.prompt().strip()
                except (EOFError, OSError):
                    self.pty.state = State.RAW
                    self.running = False
                    continue

                if line == "":
                    continue

                self.dispatch_line(line)
            except KeyboardInterrupt:
                continue

    def dispatch_line(self, line: str):
        """ Parse the given line of command input and dispatch a command """

        try:
            # Spit the line with shell rules
            argv = shlex.split(line)
        except ValueError as e:
            util.error(e.args[0])
            return

        # Search for a matching command
        for command in self.commands:
            if command.PROG == argv[0]:
                break
        else:
            util.error(f"{argv[0]}: unknown command")
            return

        try:
            # Parse the arguments
            args = command.parser.parse_args(argv[1:])

            # Run the command
            command.run(args)
        except SystemExit:
            # The arguments were icncorrect
            return


class CommandLexer(RegexLexer):

    tokens = {}

    @classmethod
    def build(cls, commands: List["CommandDefinition"]) -> "CommandLexer":
        """ Build the RegexLexer token list from the command definitions """

        root = []
        for command in commands:
            root.append(("^" + re.escape(command.PROG), Name.Function, command.PROG))
            mode = []
            for args, descr in command.ARGS.items():
                for arg in args.split(","):
                    if not arg.startswith("-"):
                        continue
                    if descr[0] != Complete.NONE:
                        # Enter param state
                        mode.append((r"\s+" + re.escape(arg), descr[1], "param"))
                    else:
                        # Don't enter param state
                        mode.append((r"\s+" + re.escape(arg), descr[1]))
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

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        self.pty = pty

    def get_completions(self, document: Document, complete_event: CompleteEvent):

        before = document.text_before_cursor.split()[-1]
        path, partial_name = os.path.split(before)

        if path == "":
            path = "."

        pipe = self.pty.subprocess(f"ls -1 -a {shlex.quote(path)}", "r")

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

    def __init__(self, pty: "PtyHandler"):
        self.pty = pty

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
        self, pty: "pwncat.pty.PtyHandler", commands: List["CommandDefinition"]
    ):
        """ Construct a new command completer """

        self.layers = {}
        local_file_completer = LocalPathCompleter(pty)
        remote_file_completer = RemotePathCompleter(pty)

        for command in commands:
            self.layers[command.PROG] = [None, [], {}]
            option_names = []
            positional_completers = []
            for name_list, descr in command.ARGS.items():
                name_list = name_list.split(",")
                if descr[0] == Complete.CHOICES:
                    completer = WordCompleter(descr[3]["choices"])
                elif descr[0] == Complete.LOCAL_FILE:
                    completer = local_file_completer
                elif descr[0] == Complete.REMOTE_FILE:
                    completer = remote_file_completer
                elif descr[0] == Complete.NONE:
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

        if text.endswith(" "):
            yield from next_completer.get_completions(document, complete_event)
        else:
            yield from this_completer.get_completions(document, complete_event)
