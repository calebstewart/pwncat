#!/usr/bin/env python3

from pwncat.util import console
from pwncat.modules import ModuleFailed
from pwncat.commands.base import Complete, Parameter, CommandDefinition


def get_user_choices(command: CommandDefinition):
    if command.manager.target is None:
        return

    yield from (
        user.name
        for user in command.manager.target.run(
            "enumerate", progress=False, types=["user"]
        )
    )


class Command(CommandDefinition):
    """
    Attempt privilege escalation in the current session. This command
    may initiate new sessions along the way to attain the privileges of
    the requested user.

    The list command is simply a wrapper around enumerating "escalation.*".
    This makes the escalation workflow more straightforward, but is not
    required."""

    PROG = "escalate"
    ARGS = {
        "command": Parameter(
            Complete.CHOICES, metavar="COMMAND", choices=["list", "run"]
        ),
        "--user,-u": Parameter(
            Complete.CHOICES, metavar="USERNAME", choices=get_user_choices
        ),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        if args.command == "help":
            self.parser.print_usage()
            return

        if args.user:
            args.user = manager.target.find_user(name=args.user)
        else:
            # NOTE: this should find admin regardless of platform
            args.user = manager.target.find_user(name="root")

        if args.command == "list":
            self.list_abilities(manager, args)
        elif args.command == "run":
            with manager.target.task(
                f"escalating to [cyan]{args.user.name}[/cyan]"
            ) as task:
                self.do_escalate(manager, task, args.user)

    def list_abilities(self, manager, args):
        """This is just a wrapper for `run enumerate types=escalate.*`, but
        it makes the workflow for escalation more apparent."""

        found = False

        for escalation in manager.target.run("enumerate", types=["escalate.*"]):
            if args.user and args.user.id != escalation.uid:
                continue
            console.print(f"- {escalation.title(manager.target)}")
            found = True

        if not found and args.user:
            console.log(
                f"[yellow]warning[/yellow]: no escalations for {args.user.name}"
            )
        elif not found:
            console.log("[yellow]warning[/yellow]: no escalations found")

    def do_escalate(self, manager: "pwncat.manager.Manager", task, user, attempted=[]):
        """ Execute escalations until we find one that works """

        # Find escalations for users that weren't attempted already
        escalations = [
            e
            for e in list(manager.target.run("enumerate", types=["escalate.*"]))
            if e.uid not in attempted
        ]

        # Attempt escalation directly to the target user if possible
        for escalation in (e for e in escalations if e.uid == user.id):
            try:
                manager.target.update_task(
                    task, status=f"attempting {escalation.title(manager.target)}"
                )
                result = escalation.escalate(manager.target)
                manager.target.layers.append(result)

                manager.target.log(
                    f"escalation to {user.name} [green]successful[/green]!"
                )
                return result
            except ModuleFailed:
                pass

        # Attempt escalation to a different user and recurse
        for escalation in (e for e in escalation if e.uid != user.id):
            try:
                manager.target.update_task(
                    task, status=f"attempting {escalation.title(manager.target)}"
                )
                result = escalation.escalate(manager.target)
                manager.target.layers.append(result)

                try:
                    self.do_escalate(manager, task, user, attempted + [escalation.uid])
                except ModuleFailed:
                    manager.target.layers.pop()(manager.target)
            except ModuleFailed:
                pass

        manager.target.log("[yellow]warning[/yellow]: no working escalations found")
