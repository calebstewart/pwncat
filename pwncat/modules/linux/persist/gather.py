#!/usr/bin/env python3
import dataclasses
import socket

import pwncat
from pwncat.util import console
from pwncat.modules import BaseModule, Argument, Status, Bool, Result
import pwncat.modules.agnostic.persist


@dataclasses.dataclass
class InstalledModule(Result):
    """Represents an installed module. It contains the persistence
    database object and the underlying module object."""

    persist: pwncat.db.Persistence
    module: "pwncat.modules.persist.PersistModule"

    @property
    def category(self) -> str:
        return "Installed Modules"

    @property
    def name(self) -> str:
        return self.module.name

    @property
    def TYPE(self):
        return self.module.TYPE

    def remove(self, progress=None):
        """ Remove this module """
        self.module.run(remove=True, progress=progress, **self.persist.args)

    def escalate(self, user=None, progress=None):
        """ Escalate utilizing this persistence module """

        args = self.persist.args.copy()
        if user is not None:
            args["user"] = user

        return self.module.run(escalate=True, progress=progress, **args)

    def connect(self, user=None, progress=None):

        if user is None and self.persist.args["user"] is None:
            user = "root"
        elif (
            self.module.TYPE.__class__.ALL_USERS not in self.module.TYPE
            and user != self.persist.args["user"]
        ):
            user = self.persist.args["user"]

        args = self.persist.args.copy()
        args["user"] = user

        return self.module.run(connect=True, progress=progress, **args)

    def __str__(self) -> str:
        result = f"[blue]{self.module.name}[/blue]("
        result += ",".join(
            [
                f"[red]{key}[/red]={repr(value)}"
                for key, value in self.persist.args.items()
            ]
        )
        result += ")"
        return result


class Module(BaseModule):
    """
    Gather a list of currently installed persistence modules.
    This module allows you to perform actions such as escalation
    and removal across a list of modules. You can apply filters
    based on the arguments of specific modules or with a module
    name itself.

    If you provide an argument filter then only modules with a
    matching argument name will be displayed.
    """

    ARGUMENTS = {
        "host": Argument(
            str, default=None, help="The hostname, IP or host hash to lookup"
        ),
        "module": Argument(str, default=None, help="Module name to look for"),
        "escalate": Argument(
            Bool, default=False, help="Utilize matched modules for escalation"
        ),
        "remove": Argument(Bool, default=False, help="Remove all matched modules"),
    }
    ALLOW_KWARGS = True
    PLATFORM = None

    def run(self, host, module, escalate, remove, **kwargs):
        """ Execute this module """

        query = get_session().query(pwncat.db.Persistence)

        if host is not None:
            row = get_session().query(pwncat.db.Host).filter_by(hash=host).first()
            if row is None:
                row = get_session().query(pwncat.db.Host).filter_by(ip=host).first()
            if row is None:
                try:
                    row = (
                        get_session()
                        .query(pwncat.db.Host)
                        .filter_by(ip=socket.gethostbyname(host))
                        .first()
                    )
                except socket.gaierror:
                    row = None
            if row is None:
                return
            query = query.filter_by(host_id=row.id)
        elif pwncat.victim is not None:
            query = query.filter_by(host_id=pwncat.victim.host.id)

        if module is not None:
            query = query.filter_by(method=module)

        # Grab all the rows
        # We also filter here for any other key-value arguments passed
        # to the `run` call. We ensure the relevant key exists, and
        # that it is equal to the specified value, unless the key is None.
        # If a key is None in the database, we assume it can take on any
        # value and utilize it as is. This is mainly for the `user` argument
        # as some persistence methods apply to all users.
        modules = [
            InstalledModule(
                persist=row,
                module=pwncat.modules.find(row.method, ignore_platform=True),
            )
            for row in query.all()
            if all(
                [
                    key in row.args
                    and (row.args[key] == value or row.args[key] is None)
                    for key, value in kwargs.items()
                ]
            )
        ]

        if remove:
            for module in modules:
                yield Status(f"removing {module.name}")
                module.remove(progress=self.progress)
            return

        if escalate:
            for module in modules:
                yield Status(f"escalating w/ [cyan]{module.name}[/cyan]")
                try:
                    # User is a special case. It can be passed on because some modules
                    # apply to all users, which means their `args` will contain `None`.
                    if "user" in kwargs:
                        module.escalate(user=kwargs["user"], progress=self.progress)
                    else:
                        module.escalate(progress=self.progress)
                    # Escalation succeeded!
                    return
                except pwncat.modules.PersistError:
                    # Escalation failed
                    pass

        yield from modules
