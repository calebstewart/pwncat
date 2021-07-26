"""
A socket bind channel. This is slightly counter-intuitive. In this case
``bind`` is from an attacker standpoint. The attacking machine will bind, and
listing for connections from the target. In this case, the target payload
would have been a reverse shell payload.

The only required argument for a bind channel is the port number. By default,
the channel will listen on all interfaces (bound to ``0.0.0.0``).
"""
import socket
import errno

from rich.progress import Progress, BarColumn

from pwncat.channel import ChannelError
from pwncat.channel.socket import Socket


class Bind(Socket):
    """
    Implements a channel which rides over a shell attached
    directly to a socket. This channel will listen for incoming
    connections on the specified port, and assume the resulting
    connection is a shell from the victim.
    """

    def __init__(self, port: int, host: str = None, **kwargs):

        if not host or host == "":
            host = "0.0.0.0"

        if port is None:
            raise ChannelError(self, "no port specified")

        super().__init__(client=None, host=host, port=port, **kwargs)

        self.address = (host, port)

        try:
            self.server = socket.create_server((host, port), reuse_port=True)
        except OSError as exc:
            error_message = str(exc)

            if exc.args[0] == errno.EACCES:
                # See `/proc/sys/net/ipv4/ip_unprivileged_port_start`
                error_message = "unable to listen on a privileged port" +\
                    "\nusually ports in the range 0-1023 are restricted" +\
                    "\n[green][TRY][/green]: try to run `pwncat` as `[red]root[/red]`"
            elif exc.args[0] == errno.EADDRINUSE:
                error_message = "port is already in use"
            elif exc.args[0] == errno.EADDRNOTAVAIL:
                error_message = "unable to bind on given address"

            raise ChannelError(self, error_message)

    def connect(self):

        with Progress(
            f"bound to [blue]{self.host}[/blue]:[cyan]{self.port}[/cyan]",
            BarColumn(bar_width=None),
            transient=True,
        ) as progress:
            progress.add_task("listening", total=1, start=False)

            try:
                # Wait for a connection
                (client, address) = self.server.accept()
                self._socket_connected(client)
            except KeyboardInterrupt:
                raise ChannelError(self, "listener aborted")
            finally:
                self.server.close()

            progress.log(
                f"[green]received[/green] connection from [blue]{address[0]}[/blue]:[cyan]{address[1]}[/cyan]"
            )
