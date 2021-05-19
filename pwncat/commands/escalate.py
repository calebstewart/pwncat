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


class Link:
    """ Link in the escalation chain """

    def __init__(self, old_session, escalation, result):

        self.old_session = old_session
        self.escalation = escalation
        self.result = result

    def leave(self):

        if self.escalation.type == "escalate.spawn":
            self.result.log(
                "leaving behind open session as [cyan]{self.old_session.current_user().name}[/cyan]"
            )

        self.old_session.manager.target = self.old_session

        if self.escalation.type == "escalate.replace":
            # Exit out of the subshell
            self.old_session.layers.pop()(self.old_session)

    def __str__(self):
        return self.escalation.title(self.old_session)


class Command(CommandDefinition):
    """
    Attempt privilege escalation in the current session. This command
    may initiate new sessions along the way to attain the privileges of
    the requested user.

    Escalation can happen either directly or recursively. In either case,
    each escalation may result in either replacing the user in the active
    session or spawning a new session. In the case of a new session, you
    should have configurations such as `lhost` and `lport` set prior to
    executing the escalation in case a reverse connection is needed.

    After escalation, if multiple stages were executed within an active
    session, you can use the `leave` command to back out of the users.
    This is useful for situations where escalation was achieved through
    peculiar ways (such as executing a command from `vim`).

    The list command is simply a wrapper around enumerating "escalation.*".
    This makes the escalation workflow more straightforward, but is not
    required."""

    PROG = "escalate"
    ARGS = {
        "command": Parameter(
            Complete.CHOICES,
            metavar="COMMAND",
            choices=["list", "run"],
            help="The action to take (list/run)",
        ),
        "--user,-u": Parameter(
            Complete.CHOICES,
            metavar="USERNAME",
            choices=get_user_choices,
            help="The target user for escalation.",
        ),
        "--recursive,-r": Parameter(
            Complete.NONE,
            action="store_true",
            help="Attempt recursive escalation through multiple users",
        ),
    }

    def run(self, manager: "pwncat.manager.Manager", args):

        if args.command == "help":
            self.parser.print_usage()
            return

        if args.command == "list":
            self.list_abilities(manager, args)
        elif args.command == "run":

            if args.user:
                args.user = manager.target.find_user(name=args.user)
            else:
                # NOTE: this should find admin regardless of platform
                args.user = manager.target.find_user(name="root")

            with manager.target.task(
                f"escalating to [cyan]{args.user.name}[/cyan]"
            ) as task:
                self.do_escalate(manager, task, args.user, args)

    def list_abilities(self, manager, args):
        """This is just a wrapper for `run enumerate types=escalate.*`, but
        it makes the workflow for escalation more apparent."""

        found = False

        if args.user:
            args.user = manager.target.find_user(name=args.user)

        for escalation in manager.target.run("enumerate", types=["escalate.*"]):
            if args.user and args.user.id != escalation.uid:
                continue
            console.print(f"- {escalation.title(manager.target)}")
            found = True

        if not found and args.user:
            console.log(
                f"[yellow]warning[/yellow]: no direct escalations for {args.user.name}"
            )
        elif not found:
            console.log("[yellow]warning[/yellow]: no direct escalations found")

    def do_escalate(self, manager: "pwncat.manager.Manager", task, user, args):
        """ Execute escalations until we find one that works """

        attempted = []
        chain = []
        original_user = manager.target.current_user()
        original_session = manager.target
        failed = []

        while True:

            # Grab the current user in the active session
            current_user = manager.target.current_user()

            # Find escalations for users that weren't attempted already
            escalations = [
                e
                for e in list(manager.target.run("enumerate", types=["escalate.*"]))
                if (e.source_uid is None or e.source_uid == current_user.id)
                and e not in failed
                and e.uid not in attempted
            ]

            if not escalations:
                try:
                    # This direction failed. Go back up and try again.
                    chain.pop().leave()
                    continue
                except IndexError:
                    manager.target.log(
                        "[red]error[/red]: no working escalation paths found for {user.name}"
                    )
                    break

            # Attempt escalation directly to the target user if possible
            for escalation in (e for e in escalations if e.uid == user.id):
                try:
                    original_session.update_task(
                        task, status=f"attempting {escalation.title(manager.target)}"
                    )
                    result = escalation.escalate(manager.target)

                    # Construct the escalation link
                    link = Link(manager.target, escalation, result)

                    # Track the result object either as a new session or a subshell
                    if escalation.type == "escalate.replace":
                        manager.target.layers.append(result)
                    else:
                        manager.target = result

                    # Add our link to the chain
                    chain.append(link)

                    manager.log(
                        f"escalation to {user.name} [green]successful[/green] using:"
                    )
                    for link in chain:
                        manager.print(f" - {link}")

                    return result
                except ModuleFailed:
                    failed.append(e)

            if not args.recursive:
                manager.target.log(
                    f"[red]error[/red]: no working direct escalations to {user.name}"
                )
                return

            # Attempt escalation to a different user and recurse
            for escalation in (e for e in escalations if e.uid != user.id):
                try:
                    original_session.update_task(
                        task, status=f"attempting {escalation.title(manager.target)}"
                    )
                    result = escalation.escalate(manager.target)
                    link = Link(manager.target, escalation, result)

                    if escalation.type == "escalate.replace":
                        manager.target.layers.append(result)
                    else:
                        manager.target = result

                    chain.append(link)
                    attempted.append(escalation.uid)
                    break
                except ModuleFailed:
                    failed.append(e)
