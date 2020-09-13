#!/usr/bin/env python3
import pwncat
from pwncat.commands.base import CommandDefinition, Parameter, Complete, Group


class Command(CommandDefinition):
    """
    Reset the prompt used for shells in pwncat. This allows you to choose
    between the fancier colored prompt and more basic prompt. You can
    also specify a custom prompt if you'd like.

    This is mainly useful for basic shells such as /bin/sh or /bin/dash
    which do not support the nicer prompts by default.
    """

    PROG = "prompt"
    GROUPS = {"mutex": Group(mutex=True, required=True)}
    ARGS = {
        "--basic,-b": Parameter(
            Complete.NONE,
            group="mutex",
            action="store_true",
            help="Set a basic prompt with no color or automatic system information. There _should_ be no reason to use that anymore (unless your local terminal has no ANSI support)",
        ),
        "--fancy,-f": Parameter(
            Complete.NONE,
            group="mutex",
            action="store_true",
            help="Set a fancier prompt including auto-user, hostname, cwd information",
        ),
    }

    def run(self, args):

        if args.fancy:
            pwncat.victim.remote_prompt = """$(command printf "\033[01;31m(remote)\033[0m \033[01;33m$(whoami)@$(hostname)\033[0m:\033[1;36m$PWD\033[0m$ ")"""
        else:
            pwncat.victim.remote_prompt = f"(remote) {pwncat.victim.host.ip}:$PWD\\$ "

        pwncat.victim.reset(hard=False)
