"""
Utilize legitimate authentication credentials to create a channel over
an SSH connection. This module simply opens an SSH channel, starts a
shell and grabs a PTY. It then wraps the SSH channel in a pwncat channel.

This module requires a host, user and either a password or identity (key) file.
An optional port argument is also accepted.
"""
import os
import socket
from typing import Union, TextIO, Optional

import paramiko
from prompt_toolkit import prompt

from pwncat.channel import Channel, ChannelError, ChannelClosed


class Ssh(Channel):
    """Wrap SSH shell channel in a pwncat channel."""

    def __init__(
        self,
        host: str,
        user: str,
        port: int = 22,
        password: str = None,
        identity: str = None,
        **kwargs,
    ):
        super().__init__(host, port, user, password)

        if port is None:
            port = 22

        if isinstance(port, str):
            try:
                port = int(port)
            except ValueError:
                raise ChannelError(self, "invalid port")

        if not user or user is None:
            raise ChannelError(self, "you must specify a user")

        if password is None and identity is None:
            password = prompt("Password: ", is_password=True)

        try:
            client = paramiko.client.SSHClient()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)

            client.connect(
                hostname=host,
                port=port,
                username=user,
                password=password,
                pkey=load_private_key(identity),
                allow_agent=True,
                look_for_keys=False,
            )

            columns, rows = os.get_terminal_size(0)
            shell = client.invoke_shell(width=columns, height=rows)
            shell.setblocking(0)

            self.client = shell
            self.address = (host, port)
            self._connected = True

        except paramiko.ssh_exception.AuthenticationException as exc:
            raise ChannelError(self, f"ssh authentication failed: {str(exc)}") from exc
        except (paramiko.ssh_exception.SSHException, socket.error) as exc:
            raise ChannelError(self, f"ssh connection failed: {str(exc)}") from exc

    @property
    def connected(self):
        return self._connected

    def close(self):
        self._connected = False
        self.client.close()

    def send(self, data: bytes):
        """Send data to the remote shell. This is a blocking call
        that only returns after all data is sent."""

        self.client.sendall(data)

        return len(data)

    def recv(self, count: Optional[int] = None) -> bytes:
        """Receive data from the remote shell

        If your channel class does not implement ``peak``, a default
        implementation is provided. In this case, you can use the
        ``_pop_peek`` to get available peek buffer data prior to
        reading data like a normal ``recv``.

        :param count: maximum number of bytes to receive (default: unlimited)
        :type count: int
        :return: the data that was received
        :rtype: bytes
        """

        if self.peek_buffer:
            data = self.peek_buffer[:count]
            self.peek_buffer = self.peek_buffer[count:]

            if len(data) >= count:
                return data
        else:
            data = b""

        try:
            data += self.client.recv(count - len(data))
            if data == b"":
                raise ChannelClosed(self)
        except socket.timeout:
            pass

        return data


def load_private_key(identity: Union[str, TextIO], passphrase: str = None):
    """Load a private key and return the appropriate PKey object"""

    if identity is None:
        return None

    try:
        if isinstance(identity, str):
            return paramiko.pkey.load_private_key_file(
                os.path.expanduser(identity), password=passphrase
            )

        identity.seek(0)
        return paramiko.pkey.load_private_key(identity.read(), password=passphrase)
    except paramiko.PasswordRequiredException:
        # Bad passphrase
        if passphrase is not None:
            raise

        try:
            # No passphrase, prompt for one
            passphrase = prompt("Private Key Passphrase: ", is_password=True)
        except KeyboardInterrupt:
            passphrase = None

        # No passphrase given, re-raise
        if passphrase is None:
            raise

        # Try again with the given passphrase
        return load_private_key(identity, passphrase=passphrase)
