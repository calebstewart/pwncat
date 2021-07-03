#!/usr/bin/env python3
from pwncat.commands.base import CommandDefinition, Complete, Parameter
from pwncat.util import console
import pwncat


class Command(CommandDefinition):
    """
    Display remote system information including host ID, IP address,
    architecture, kernel version, distribution and init system. This
    command also provides the capability to view installed services
    if the init system is supported by ``pwncat``.
    """

    PROG = "sysinfo"
    ARGS = {
        "--services,-s": Parameter(
            Complete.NONE, action="store_true", help="List all services and their state"
        )
    }

    def run(self, args):

        if args.services:
            for service in pwncat.victim.services:
                if service.running:
                    console.print(
                        f"[green]{service.name}[/green] - {service.description}"
                    )
                else:
                    console.print(f"[red]{service.name}[/red] - {service.description}")
        else:
            console.print(f"Host ID: [cyan]{pwncat.victim.host.hash}[/cyan]")
            console.print(
                f"Remote Address: [green]{pwncat.victim.client.getpeername()}[/green]"
            )
            console.print(f"Architecture: [red]{pwncat.victim.host.arch}[/red]")
            console.print(f"Kernel Version: [red]{pwncat.victim.host.kernel}[/red]")
            console.print(f"Distribution: [red]{pwncat.victim.host.distro}[/red]")
            console.print(f"Init System: [blue]{pwncat.victim.host.init}[/blue]")
