"""
Utilize legitimate authentication credentials to create a channel over
an SSH connection. This module simply opens an SSH channel, starts a
shell and grabs a PTY. It then wraps the SSH channel in a pwncat channel.

This module requires a host, user and either a password or identity (key) file.
An optional port argument is also accepted.
"""
import os
import socket
from typing import Optional

import paramiko
from prompt_toolkit import prompt

from pwncat.channel import Channel, ChannelError


class Ssh(Channel):
    """ Wrap SSH shell channel in a pwncat channel. """

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

        if not user or user is None:
            raise ChannelError("you must specify a user")

        if password is None and identity is None:
            password = prompt("Password: ", is_password=True)

        try:
            client = paramiko.client.SSHClient()
            client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy)

            try:
                client.connect(
                    hostname=host,
                    port=port,
                    username=user,
                    password=password,
                    key_filename=os.path.expanduser(identity),
                    allow_agent=True,
                    look_for_keys=False,
                )
            except paramiko.ssh_exception.PasswordRequiredException:
                passphrase = prompt("RSA Private Key Passphrase: ", is_password=True)
                client.connect(
                    hostname=host,
                    port=port,
                    username=user,
                    password=password,
                    key_filename=os.path.expanduser(identity),
                    allow_agent=True,
                    look_for_keys=False,
                    passphrase=passphrase,
                )

            columns, rows = os.get_terminal_size(0)
            shell = client.invoke_shell(width=columns, height=rows)
            shell.setblocking(0)

            self.client = shell
            self.address = (host, port)
            self._connected = True

        except paramiko.ssh_exception.AuthenticationException as exc:
            raise ChannelError(f"ssh authentication failed: {str(exc)}") from exc
        except (paramiko.ssh_exception.SSHException, socket.error) as exc:
            raise ChannelError(f"ssh connection failed: {str(exc)}") from exc

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
