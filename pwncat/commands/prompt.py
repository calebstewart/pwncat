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
            help="Set a basic prompt with no color or automatic system information",
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
            pwncat.victim.remote_prefix = "\\[\\033[01;31m\\](remote)\\[\\033[00m\\]"
            pwncat.victim.remote_prompt = (
                "\\[\\033[01;33m\\]\\u@\\h\\[\\033[00m\\]:\\["
                "\\033[01;36m\\]\\w\\[\\033[00m\\]\\$ "
            )
        else:
            pwncat.victim.remote_prefix = "(remote)"
            pwncat.victim.remote_prompt = f"{pwncat.victim.host.ip}:$PWD\\$ "

        pwncat.victim.reset(hard=False)
