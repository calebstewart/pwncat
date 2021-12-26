#!/usr/bin/env python3
import ssl
import datetime
import tempfile

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from pwncat.channel import ChannelError
from pwncat.channel.bind import Bind


class SSLBind(Bind):
    def __init__(self, certfile: str = None, keyfile: str = None, **kwargs):
        super().__init__(**kwargs)

        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        if certfile is None and keyfile is None:
            certfile = keyfile = self._generate_self_signed_cert()

        self.context.load_cert_chain(certfile, keyfile)

        # self.server = self.context.wrap_socket(self.server)

    def _socket_connected(self, client):
        try:
            client = self.context.wrap_socket(client, server_side=True)
        except ssl.SSLError as exc:
            raise ChannelError(self, str(exc))

        super()._socket_connected(client)

    def connect(self):

        try:
            super().connect()
        except ssl.SSLError as exc:
            raise ChannelError(self, str(exc))

    def _generate_self_signed_cert(self):
        """Generate a self-signed certificate"""

        with tempfile.NamedTemporaryFile("wb", delete=False) as filp:
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            filp.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

            # Literally taken from: https://cryptography.io/en/latest/x509/tutorial/
            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Company"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"mysite.com"),
                ]
            )
            cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.datetime.utcnow())
                .not_valid_after(
                    datetime.datetime.utcnow() + datetime.timedelta(days=365)
                )
                .add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                    critical=False,
                )
                .sign(key, hashes.SHA256())
            )

            filp.write(cert.public_bytes(serialization.Encoding.PEM))

            return filp.name
