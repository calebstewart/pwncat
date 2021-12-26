#!/usr/bin/env python3
import ssl

from pwncat.channel import ChannelError
from pwncat.channel.connect import Connect


class SSLConnect(Connect):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _socket_connected(self, client):
        try:
            self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.context.check_hostname = False
            self.context.verify_mode = ssl.VerifyMode.CERT_NONE

            client = self.context.wrap_socket(client)
        except ssl.SSLError as exc:
            raise ChannelError(self, str(exc))

        super()._socket_connected(client)
