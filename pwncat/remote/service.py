#!/usr/bin/env python3
import os
import textwrap
from enum import Enum, auto
from typing import Iterator

import pwncat
from pwncat import util
from pwncat.util import Access


class ServiceState(Enum):
    RUNNING = auto()
    STOPPED = auto()
    FAILED = auto()


class RemoteService:
    """
    Abstract service interface. Interfaces for specific init systems are implemented as
    a subclass of the RemoteService class. The class methods defined here should be
    redefined to access and enumerate the underlying init system.
    
    :param name: the service name
    :param user: whether this service is a user specific service
    :param running: whether this service is currently running
    :param description: a long description for this service
    
    """

    def __init__(self, name: str, running: bool, description: str, user: bool = False):
        self.name: str = name
        self.user: bool = user
        self.running: bool = running
        self.description: str = description

    @classmethod
    def enumerate(cls, user: bool = False) -> Iterator["RemoteService"]:
        """
        Enumerate installed services on the remote host. This is overloaded for a
        specific init system.
        
        :param user: whether to enumerate user specific services
        :return: An iterator for remote service objects
        """
        raise NotImplementedError

    def start(self):
        """ Start the remote service """
        raise NotImplementedError

    def restart(self):
        """ Restart the remote service """
        raise NotImplementedError

    def stop(self):
        """ Stop the remote service """
        raise NotImplementedError

    @property
    def stopped(self) -> bool:
        """ Check if the service is stopped """
        return not self.running

    @property
    def enabled(self) -> bool:
        """ Check if the service is enabled at boot. The setter will attempt to
        enable or disable this service for auto-start. """
        raise NotImplementedError


class SystemDService(RemoteService):
    """ Wraps a remote systemd based service """

    @classmethod
    def enumerate(cls, user: bool = False) -> Iterator["RemoteService"]:
        """ Enumerate all loaded services """

        argv = ["systemctl"]
        if user:
            argv.append("--user")
        argv.extend(
            ["--type=service", "-l", "--no-pager", "--plain", "--no-legend", "--all"]
        )

        # Get the list of services
        data = pwncat.victim.env(argv, PAGER="").strip().decode("utf-8")

        # Get all the service lines from the table
        services = [line.strip() for line in data.split("\n")]

        for service in services:
            values = [v for v in service.split(" ") if v != ""]
            name = ".".join(values[0].split(".")[:-1])
            state = values[3]
            description = " ".join(values[4:])
            yield SystemDService(name, state == "running", description, user)

    @classmethod
    def find(cls, name: str, user: bool = False) -> "RemoteService":
        """ Lookup a service by name """

        argv = ["systemctl"]
        if user:
            argv.append("--user")
        argv.extend(
            [
                "list-units",
                name + ".service",
                "--type=service",
                "-l",
                "--no-pager",
                "--plain",
                "--no-legend",
            ]
        )

        # Get the list of services
        data = pwncat.victim.env(argv, PAGER="").strip().decode("utf-8")

        # Get all the service lines from the table
        services = [line.strip() for line in data.split("\n")]

        if not services or (len(services) == 1 and services[0] == ""):
            # Check w/ "list-unit-files". For some reason, disabled services
            # don't always show up with "--all"... :|
            argv = ["systemctl"]
            if user:
                argv.append("--user")
            argv.extend(
                [
                    "list-unit-files",
                    f"{name}.service",
                    "--type=service",
                    "-l",
                    "--no-pager",
                    "--plain",
                    "--no-legend",
                ]
            )
            data = pwncat.victim.env(argv, PAGER="").strip().decode("utf-8")
            services = [line.strip() for line in data.split("\n")]

            if not services or (len(services) == 1 and services[0] == ""):
                raise ValueError(name)

            values = [v for v in services[0].split(" ") if v != ""]
            if len(values) > 0:
                return SystemDService(
                    name=values[0], description="", running=False, user=user
                )
            else:
                raise ValueError(f"{name}: no such service")

        values = [v for v in services[0].split(" ") if v != ""]
        name = ".".join(values[0].split(".")[:-1])
        state = values[3]
        description = " ".join(values[4:])

        return SystemDService(name, state == "running", description, user)

    @classmethod
    def create(
        cls,
        name: str,
        description: str,
        target: str,
        runas: str,
        enable: bool,
        user: bool = False,
    ):
        """ Create a new service on the remote system. """

        if not user and pwncat.victim.whoami() != "root":
            raise PermissionError

        unit_file = textwrap.dedent(
            f"""
            [Unit]
            Description="{description}"
            
            [Service]
            Type=simple
            ExecStart={pwncat.victim.shell} -c {util.quote(target)}
            User={runas}
            
            [Install]
            WantedBy=multi-user.target
            """
        ).lstrip()

        unit_file_path = "/usr/local/lib/systemd/system"
        if user:
            XDG_CONFIG_HOME = pwncat.victim.getenv("XDG_CONFIG_HOME").rstrip("/")
            if XDG_CONFIG_HOME == "":
                unit_file_path = os.path.join(
                    pwncat.victim.current_user.homedir, ".config/systemd/user"
                )
            else:
                unit_file_path = f"{XDG_CONFIG_HOME}/systemd/user"

        # Create the directory if needed
        if Access.DIRECTORY not in pwncat.victim.access(unit_file_path):
            pwncat.victim.env(["mkdir", "-p", unit_file_path])

        # Create the service file
        with pwncat.victim.open(
            os.path.join(unit_file_path, f"{name}.service"), "w", length=len(unit_file)
        ) as filp:
            filp.write(unit_file)

        # Set the permissions
        pwncat.victim.env(
            ["chmod", "644", os.path.join(unit_file_path, f"{name}.service")]
        )

        # Reload the units
        argv = ["systemctl"]
        if user:
            argv.append("--user")
        argv.extend(["daemon-reload"])
        pwncat.victim.env(argv)

        # Enable the service
        if enable:
            argv = ["systemctl"]
            if user:
                argv.append("--user")
            argv.extend(["enable", f"{name}.service"])
            pwncat.victim.env(argv)

        return cls.find(name)

    def start(self):

        if pwncat.victim.whoami() != "root" and not self.user:
            raise PermissionError(f"{self.name}: permission denied")

        argv = ["systemctl"]
        if self.user:
            argv.append("--user")

        argv.extend(["start", self.name])

        pwncat.victim.env(argv)

    def restart(self):

        if pwncat.victim.whoami() != "root" and not self.user:
            raise PermissionError(f"{self.name}: permission denied")

        argv = ["systemctl"]
        if self.user:
            argv.append("--user")

        argv.extend(["restart", self.name])

        pwncat.victim.env(argv)

    def stop(self):

        if pwncat.victim.whoami() != "root" and not self.user:
            raise PermissionError(f"{self.name}: permission denied")

        argv = ["systemctl"]
        if self.user:
            argv.append("--user")

        argv.extend(["stop", self.name])

        pwncat.victim.env(argv)

    @property
    def status(self):

        argv = ["systemctl"]
        if self.user:
            argv.append("--user")

        argv.extend(["status", self.name, "-l"])

        # Get the status of the service without a pager
        result = pwncat.victim.env(argv, PAGER="")

        return result.strip.decode("utf-8")

    @property
    def enabled(self):
        status = self.status

        for line in status.split("\n"):
            line = line.strip().lower()
            if line.startswith("Loaded:"):
                if line.split(";")[1].strip() == "enabled":
                    return True
                else:
                    return False

        return False


service_map = {util.Init.SYSTEMD: SystemDService}
