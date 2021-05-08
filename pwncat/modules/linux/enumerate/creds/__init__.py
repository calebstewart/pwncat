#!/usr/bin/env python3

import rich.markup

from pwncat.db import Fact


class PasswordData(Fact):
    """A password possible extracted from a remote file
    `filepath` and `lineno` may be None signifying this
    password did not come from a file directly.
    """

    def __init__(self, source, password, filepath, lineno, uid):
        super().__init__(source=source, types=["creds.password"])

        self.password: str = password
        self.filepath: str = filepath
        self.lineno: int = lineno
        self.uid: int = uid  # We are Linux-specific here so this can be a literal UID

    def title(self, session):
        if self.password is not None:
            result = f"Potential Password [cyan]{rich.markup.escape(repr(self.password))}[/cyan]"
            if self.uid is not None:
                result += f" for [blue]{rich.markup.escape(session.find_user(uid = self.uid).name)}[/blue]"
            if self.filepath is not None:
                result += f" ({rich.markup.escape(self.filepath)}:{self.lineno})"
        else:
            result = f"Potential Password at [cyan]{rich.markup.escape(self.filepath)}[/cyan]:{self.lineno}"

        return result


class PrivateKeyData(Fact):
    """A private key found on the remote file system or known
    to be applicable to this system in some way."""

    def __init__(self, source, path, uid, content, encrypted):
        super().__init__(source=source, types=["creds.private_key"])

        self.uid: int = uid
        """ The uid we believe the private key belongs to """
        self.path: str = path
        """ The path to the private key on the remote host """
        self.content: str = content
        """ The actual content of the private key """
        self.encrypted: bool = encrypted
        """ Is this private key encrypted? """

    def __str__(self):
        if self.uid == 0:
            color = "red"
        else:
            color = "green"
        return f"Potential private key for [{color}]{self.uid}[/{color}] at [cyan]{rich.markup.escape(self.path)}[/cyan]"

    @property
    def description(self) -> str:
        return self.content
