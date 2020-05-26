#!/usr/bin/env python3

from colorama import Fore

from pwncat.commands.base import CommandDefinition, Complete, Parameter
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
                    print(
                        f"{Fore.GREEN}{service.name}{Fore.RESET} - {service.description}"
                    )
                else:
                    print(
                        f"{Fore.RED}{service.name}{Fore.RESET} - {service.description}"
                    )
        else:
            print(f"Host ID: {Fore.CYAN}{pwncat.victim.host.hash}{Fore.RESET}")
            print(
                f"Remote Address: {Fore.GREEN}{pwncat.victim.client.getpeername()}{Fore.RESET}"
            )
            print(f"Architecture: {Fore.RED}{pwncat.victim.host.arch}{Fore.RESET}")
            print(f"Kernel Version: {Fore.RED}{pwncat.victim.host.kernel}{Fore.RESET}")
            print(f"Distribution: {Fore.RED}{pwncat.victim.host.distro}{Fore.RESET}")
            print(f"Init System: {Fore.BLUE}{pwncat.victim.host.init}{Fore.RESET}")
