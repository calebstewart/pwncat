#!/usr/bin/env python3
from typing import List

from rich.prompt import Prompt

from pwncat.util import console
from pwncat.facts import Implant, KeepImplantFact
from pwncat.modules import Bool, Status, Argument, BaseModule, ModuleFailed


class Module(BaseModule):
    """Interact with installed implants in an open session. This module
    provides the ability to remove implants as well as manually escalate
    with a given implant. Implants implementing local escalation will
    automatically be picked up by the `escalate` command, however this
    module provides an alternative way to trigger escalation manually."""

    PLATFORM = None
    """ No platform restraints """
    ARGUMENTS = {
        "list": Argument(Bool, default=False, help="list installed implants"),
        "remove": Argument(Bool, default=False, help="remove installed implants"),
        "escalate": Argument(
            Bool, default=False, help="escalate using an installed local implant"
        ),
    }

    def run(self, session, remove, escalate, **kwargs):
        """Perform the requested action"""

        if sum([remove, escalate, kwargs.get("list")]) > 1:
            raise ModuleFailed("expected one of escalate, remove or list")

        if remove is False and escalate is False:
            kwargs["list"] = True

        # Look for matching implants
        implants = list(
            implant
            for implant in session.run("enumerate", types=["implant.*"])
            if not escalate
            or kwargs.get("list")
            or "implant.replace" in implant.types
            or "implant.spawn" in implant.types
        )

        if not implants:
            console.print("No installed implants.")
            return

        try:
            session._progress.stop()

            console.print("Found the following implants:")
            for i, implant in enumerate(implants):
                console.print(f"{i+1}. {implant.title(session)}")

            if remove:
                prompt = "Which should we remove (e.g. '1 2 4', default: all)? "
            elif escalate:
                prompt = "Which should we attempt escalation with (e.g. '1 2 4', default: all)? "
            else:
                return

            while True:
                selections = Prompt.ask(prompt, console=console)
                if selections == "":
                    break

                try:
                    implant_ids = [int(idx.strip()) for idx in selections]
                    # Filter the implants
                    implants: List[Implant] = [implants[i - 1] for i in implant_ids]
                    break
                except (IndexError, ValueError):
                    console.print("[red]error[/red]: invalid selection!")

        finally:
            session._progress.start()

        nremoved = 0

        for implant in implants:
            if remove:
                try:
                    yield Status(f"removing: {implant.title(session)}")
                    implant.remove(session)
                    session.target.facts.remove(implant)
                    nremoved += 1
                except KeepImplantFact:
                    # Remove implant types but leave the fact
                    implant.types.remove("implant.remote")
                    implant.types.remove("implant.replace")
                    implant.types.remove("implant.spawn")
                    nremoved += 1
                except ModuleFailed:
                    session.log(
                        f"[red]error[/red]: removal failed: {implant.title(session)}"
                    )
            elif escalate:
                try:
                    yield Status(
                        f"attempting escalation with: {implant.title(session)}"
                    )
                    result = implant.escalate(session)

                    if "implant.spawn" in implant.types:
                        # Move to the newly established session
                        session.manager.target = result
                    else:
                        # Track the new shell layer in the current session
                        session.layers.append(result)
                        session.platform.refresh_uid()

                    session.log(
                        f"escalation [green]succeeded[/green] with: {implant.title(session)}"
                    )
                    break
                except ModuleFailed:
                    continue
        else:
            if escalate:
                raise ModuleFailed("no working local escalation implants found")

        if nremoved:
            session.log(f"removed {nremoved} implants from target")

        # Save database modifications
        session.db.transaction_manager.commit()
