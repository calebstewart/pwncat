"""
Utilize legitimate authentication credentials to create a channel over
an SSH connection. This module simply opens an SSH channel, starts a
shell and grabs a PTY. It then wraps the SSH channel in a pwncat channel.

This module requires a host, user and either a password or identity (key) file.
An optional port argument is also accepted.
"""
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
            # Connect to the remote host's ssh server
            sock = socket.create_connection((host, port))
        except Exception as exc:
            raise ChannelError(str(exc))

        # Create a paramiko SSH transport layer around the socket
        t = paramiko.Transport(sock)
        try:
            t.start_client()
        except paramiko.SSHException:
            sock.close()
            raise ChannelError("ssh negotiation failed")

        if identity is not None:
            try:
                # Load the private key for the user
                key = paramiko.RSAKey.from_private_key_file(identity)
            except:
                password = prompt("RSA Private Key Passphrase: ", is_password=True)
                try:
                    key = paramiko.RSAKey.from_private_key_file(identity, password)
                except:
                    raise ChannelError("invalid private key or passphrase")

            # Attempt authentication
            try:
                t.auth_publickey(user, key)
            except paramiko.ssh_exception.AuthenticationException as exc:
                raise ChannelError(str(exc))
        else:
            try:
                t.auth_password(user, password)
            except paramiko.ssh_exception.AuthenticationException as exc:
                raise ChannelError(str(exc))

        if not t.is_authenticated():
            t.close()
            sock.close()
            raise ChannelError("authentication failed")

        # Open an interactive session
        chan = t.open_session()
        chan.get_pty()
        chan.invoke_shell()
        chan.setblocking(0)

        self.client = chan
        self.address = (host, port)
        self._connected = True

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
