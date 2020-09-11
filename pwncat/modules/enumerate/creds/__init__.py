#!/usr/bin/env python3
import dataclasses

import pwncat


@dataclasses.dataclass
class PasswordData:
    """ A password possible extracted from a remote file
    `filepath` and `lineno` may be None signifying this
    password did not come from a file directly.
    """

    password: str
    filepath: str
    lineno: int

    def __str__(self):
        if self.password is not None:
            result = f"Potential Password [cyan]{repr(self.password)}[/cyan]"
            if self.filepath is not None:
                result += f" ({self.filepath}:{self.lineno})"
        else:
            result = f"Potential Password at [cyan]{self.filepath}[/cyan]:{self.lineno}"
        return result


@dataclasses.dataclass
class PrivateKeyData:
    """ A private key found on the remote file system or known
    to be applicable to this system in some way. """

    uid: int
    """ The user we believe the private key belongs to """
    path: str
    """ The path to the private key on the remote host """
    content: str
    """ The actual content of the private key """
    encrypted: bool
    """ Is this private key encrypted? """

    def __str__(self):
        if self.uid == 0:
            color = "red"
        else:
            color = "green"
        return f"Potential private key for [{color}]{self.user.name}[/{color}] at [cyan]{self.path}[/cyan]"

    @property
    def description(self) -> str:
        return self.content

    @property
    def user(self):
        return pwncat.victim.find_user_by_id(self.uid)
