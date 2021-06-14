#!/usr/bin/env python3
import ssl

from pwncat.channel import ChannelError
from pwncat.channel.bind import Bind


class SSLBind(Bind):
    def __init__(self, certfile: str = None, keyfile: str = None, **kwargs):
        super().__init__(**kwargs)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile, keyfile)

        self.server = self.context.wrap_socket(self.server)

    def connect(self):

        try:
            super().connect()
        except ssl.SSLError as exc:
            raise ChannelError(self, str(exc))
