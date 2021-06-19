"""
The manager is the core object within pwncat. A manager is responsible for maintaining
configuration, terminal state, and maintaining all active pwncat sessions. A manager
can have zero or more sessions active at any given time. It is recommended to create
a manager through the context manager syntax. In this way, pwncat will automatically
disconnect from active sessions and perform any required cleanup prior to exiting
even if there was an uncaught exception. The normal method of creating a manager is:

.. code-block:: python

    with pwncat.manager.Manager() as manager:
        # Do something with your manager, like set a configuration item
        # or open a connection
        session = manager.create_session(platform="linux", host="192.168.1.1", port=4444)

"""
import os
import ssl
import sys
import queue
import signal
import socket
import fnmatch
import pkgutil
import datetime
import tempfile
import threading
import contextlib
from io import TextIOWrapper
from enum import Enum, auto
from typing import Dict, List, Tuple, Union, Callable, Optional, Generator

import ZODB
import zodburi
import rich.progress
import persistent.list
from cryptography import x509
from cryptography.x509.oid import NameOID
from prompt_toolkit.shortcuts import confirm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import pwncat.db
import pwncat.facts
import pwncat.modules
import pwncat.modules.enumerate
from pwncat.util import RawModeExit, console
from pwncat.config import Config
from pwncat.target import Target
from pwncat.channel import Channel, ChannelError, ChannelClosed
from pwncat.commands import CommandParser
from pwncat.platform import Platform, PlatformError
from pwncat.modules.enumerate import Scope


class InteractiveExit(Exception):
    """Indicates we should exit the interactive terminal"""


class ListenerError(Exception):
    """Raised by utility functions within the listener class.
    This is never raised in the main thread, and is only used
    to consolidate errors from various socket and ssl libraries
    when setting up and operating the listener."""


class ListenerState(Enum):
    """Background listener state"""

    STOPPED = auto()
    """ The listener is not started """
    RUNNING = auto()
    """ The listener is running """
    FAILED = auto()
    """ The listener encountered an exception and is in a failed state """


class Listener(threading.Thread):
    """Background Listener which acts a factory constructing sessions
    in the background. Listeners should not be created directly. Rather,
    you should use the ``Manager.create_listener`` method.
    """

    def __init__(
        self,
        manager: "Manager",
        address: Tuple[str, int],
        protocol: str = "socket",
        platform: Optional[str] = None,
        count: Optional[int] = None,
        established: Optional[Callable[["Session"], bool]] = None,
        ssl: bool = False,
        ssl_cert: Optional[str] = None,
        ssl_key: Optional[str] = None,
    ):
        super().__init__(daemon=True)

        self.manager: "Manager" = manager
        """ The controlling manager object """
        self.address: Tuple[str, int] = address
        """ The address to bind our listener to on the attacking machine """
        self.protocol: str = protocol
        """ Name of the channel protocol to use for incoming connections """
        self.platform: Optional[str] = platform
        """ The platform to use when automatically establishing sessions """
        self.count: Optional[int] = count
        """ The number of connections to receive before exiting """
        self.established: Optional[Callable[["Session"], bool]] = established
        """ A callback used when a new session is established """
        self.ssl: bool = ssl
        """ Whether to wrap the listener in SSL """
        self.ssl_cert: Optional[str] = ssl_cert
        """ The SSL server certificate """
        self.ssl_key: Optional[str] = ssl_key
        """ The SSL server key """
        self.state: ListenerState = ListenerState.STOPPED
        """ The current state of the listener; only set internally """
        self.failure_exception: Optional[Exception] = None
        """ An exception which was caught and put the listener in ListenerState.FAILED state """
        self._stop_event: threading.Event = threading.Event()
        """ An event used to signal the listener to stop """
        self._session_queue: queue.Queue = queue.Queue()
        """ Queue of newly established sessions. If this queue fills up, it is drained automatically. """
        self._channel_queue: queue.Queue = queue.Queue()
        """ Queue of channels waiting to be initialized in the case of an unidentified platform """
        self._session_lock: threading.Lock = threading.Lock()

    def __str__(self):
        return f"[blue]{self.address[0]}[/blue]:[cyan]{self.address[1]}[/cyan]"

    @property
    def pending(self) -> int:
        """Retrieve the number of pending channels"""

        return self._channel_queue.qsize()

    def iter_sessions(
        self, count: Optional[int] = None
    ) -> Generator["Session", None, None]:
        """
        Synchronously iterate over new sessions. This generated will
        yield sessions until no more sessions are found on the queue.
        However, more sessions may be added after iterator (or while
        iterating) over this generator. Reaching the end of this list
        when count=None does not indicate that the listener has stopped.

        :param count: the number of sessions to retreive or None for infinite
        :type count: Optional[int]
        :rtype: Generator[Session, None, None]
        """

        while True:
            if count is not None and count <= 0:
                break

            try:
                yield self._session_queue.get(block=False, timeout=None)
                if count is not None:
                    count -= 1
            except queue.Empty:
                return

    def iter_channels(
        self, count: Optional[int] = None
    ) -> Generator["Channel", None, None]:
        """
        Synchronously iterate over new channels. This generated will
        yield channels until no more channels are found on the queue.
        However, more channels may be added after iterator (or while
        iterating) over this generator. Reaching the end of this list
        when count=None does not indicate that the listener has stopped.

        :param count: number of channels to receive or None for infinite
        :type count: Optional[int]
        :rtype: Generator[Channel, None, None]
        """

        while True:
            if count is not None and count <= 0:
                break

            try:
                yield self._channel_queue.get(block=False, timeout=None)
                if count is not None:
                    count -= 1
            except queue.Empty:
                return

    def bootstrap_session(
        self, channel: pwncat.channel.Channel, platform: str
    ) -> "pwncat.manager.Session":
        """
        Establish a session from an existing channel using the specified platform.
        If platform is None, then the given channel is placed onto the uninitialized
        channel queue for later initialization.

        :param channel: the channel to initialize
        :type channel: pwncat.channel.Channel
        :param platform: name of the platform to initialize
        :type platform: Optional[str]
        :rtype: pwncat.manager.Session
        :raises:
            ListenerError: incorrect platform or channel disconnected
        """

        with self._session_lock:

            if self.count is not None and self.count <= 0:
                raise ListenerError("listener max connections reached")

            if platform is None:
                # We can't initialize this channel, so we just throw it on the queue
                self._channel_queue.put_nowait(channel)
                return None

            try:
                session = self.manager.create_session(
                    platform=platform, channel=channel
                )

                self.manager.log(
                    f"[magenta]listener[/magenta]: [blue]{self.address[0]}[/blue]:[cyan]{self.address[1]}[/cyan]: {platform} session from {channel} established"
                )

                # Call established callback for session notification
                if self.established is not None and not self.established(session):
                    # The established callback can decide to ignore an established session
                    session.close()
                    return None

                # Queue the session. This is an obnoxious loop, but
                # basically, we attempt to queue the session, and if
                # the queue is full, we remove a queued session, and
                # retry. We keep doing this until it works. This is
                # fine because the queue is just for notification
                # purposes, and the sessions are already tracked by
                # the manager.
                while True:
                    try:
                        self._session_queue.put_nowait(session)
                        break
                    except queue.Full:
                        try:
                            self._session_queue.get_nowait()
                        except queue.Empty:
                            pass

                if self.count is not None:
                    self.count -= 1
                    if self.count <= 0:
                        # Drain waiting channels
                        self.manager.log(
                            "[magenta]listener[/magenta]: [blue]{self.address[0]}[/blue]:[cyan]{self.address[0]}[/cyan]: max session count reached; shutting down"
                        )
                        self._stop_event.set()

                return session
            except (PlatformError, ChannelError) as exc:
                raise ListenerError(str(exc)) from exc

    def stop(self):
        """Stop the listener"""

        with self._session_lock:
            self.count = 0
            self._stop_event.set()

        self.join()

    def run(self):
        """Execute the listener in the background. We have to be careful not
        to trip up the manager, as this is running in a background thread."""

        try:

            # Start the listener and wrap in the SSL context
            raw_server = self._open_socket()
            server = self._ssl_wrap(raw_server)

            # Set a short timeout so we don't block the thread
            server.settimeout(1)

            self.state = ListenerState.RUNNING

            while not self._stop_event.is_set():
                try:
                    # Accept a new client connection
                    client, address = server.accept()
                except socket.timeout:
                    # No connection, loop and check if we've been stopped
                    continue

                channel = None

                try:
                    # Construct a channel around the raw client
                    channel = self._bootstrap_channel(client)

                    # If we know the platform, create the session
                    self.bootstrap_session(channel, platform=self.platform)
                except ListenerError as exc:
                    # this connection didn't establish; log it
                    self.manager.log(
                        f"[magenta]listener[/magenta]: [blue]{self.address[0]}[/blue]:[cyan]{self.address[1]}[/cyan]: connection from [blue]{address[0]}[/blue]:[cyan]{address[1]}[/cyan] aborted: {exc}"
                    )

                    if channel is not None:
                        channel.close()
                    else:
                        # Close the socket
                        client.close()

            self.state = ListenerState.STOPPED

        except Exception as exc:
            self.state = ListenerState.FAILED
            self.failure_exception = exc
            self._stop_event.set()
        finally:
            self._close_socket(raw_server, server)

            if self.count is not None and self.count <= 0:
                try:
                    # Drain waiting channels
                    while True:
                        self._channel_queue.get_nowait().close()
                except queue.Empty:
                    pass

    def _open_socket(self) -> socket.socket:
        """Open the raw socket listener and return the new socket object"""

        # Create a listener
        try:
            server = socket.create_server(
                self.address, reuse_port=True, backlog=self.count
            )

            return server
        except socket.error as exc:
            raise ListenerError(str(exc))

    def _ssl_wrap(self, server: socket.socket) -> ssl.SSLSocket:
        """Wrap the given server socket in an SSL context and return the new socket.
        If the ``ssl`` option is not set, this method simply returns the original socket."""

        if not self.ssl:
            return server

        if self.ssl_cert is None and self.ssl_key is not None:
            self.ssl_cert = self.ssl_key
        if self.ssl_key is None and self.ssl_cert is not None:
            self.ssl_key = self.ssl_cert

        if self.ssl_cert is None or self.ssl_key is None:
            with tempfile.NamedTemporaryFile("wb", delete=False) as filp:
                self.manager.log(
                    f"generating self-signed certificate at {repr(filp.name)}"
                )

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
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                        x509.NameAttribute(
                            NameOID.STATE_OR_PROVINCE_NAME, "California"
                        ),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Company"),
                        x509.NameAttribute(NameOID.COMMON_NAME, "mysite.com"),
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
                        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                        critical=False,
                    )
                    .sign(key, hashes.SHA256())
                )

                filp.write(cert.public_bytes(serialization.Encoding.PEM))

                self.ssl_cert = filp.name
                self.ssl_key = filp.name

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(self.ssl_cert, self.ssl_key)

            return context.wrap_socket(server)
        except ssl.SSLError as exc:
            raise ListenerError(str(exc))

    def _close_socket(self, raw_server: socket.socket, server: socket.socket):
        """Close the listener socket"""

        if server is not raw_server and server is not None:
            server.close()

        if raw_server is not None:
            raw_server.close()

    def _bootstrap_channel(self, client: socket.socket) -> "pwncat.channel.Channel":
        """
        Create a channel with the listener parameters around the socket.

        :param client: a newly established client socket
        :type client: socket.socket
        :rtype: pwncat.channel.Channel
        """

        try:
            channel = pwncat.channel.create(protocol=self.protocol, client=client)
        except ChannelError as exc:
            raise ListenerError(str(exc))

        return channel


class Session:
    """This class represents the container by which ``pwncat`` references
    connections to victim machines. It glues together a connected ``Channel``
    and an appropriate ``Platform`` implementation. It also provides generic
    access to the ``pwncat`` database and logging functionality."""

    def __init__(
        self,
        manager,
        platform: Union[str, Platform],
        channel: Optional[Channel] = None,
        active: bool = True,
        **kwargs,
    ):
        self.id = manager.session_id
        self.manager = manager
        self.background = None
        self._db_session = None
        self.db = manager.db.open()
        self.module_depth = 0
        self.showing_progress = True
        self.layers = []
        self.enumerate_state = {}
        self.facts = []

        self._progress = None

        # If necessary, build a new platform object
        if isinstance(platform, Platform):
            self.platform = platform
        else:
            # If necessary, build a new channel
            if channel is None:
                channel = pwncat.channel.create(**kwargs)

            # This makes logging work during the constructor
            self.platform = str(channel)

            self.platform = pwncat.platform.find(platform)(
                self,
                channel,
                log=self.config.get("log", None),
                verbose=self.config.get("verbose", False),
            )

        # Register this session with the manager
        self.manager.sessions[self.id] = self

        if active or self.manager.target is None:
            self.manager.target = self

        # Initialize the host reference
        self.hash = self.platform.get_host_hash()

        if self.target is None:
            self.register_new_host()
        else:
            self.log("loaded known host from db")

        self.platform.get_pty()

    @property
    def config(self):
        """Get the configuration object for this manager. This
        is simply a wrapper for session.manager.config to make
        accessing configuration a little easier."""
        return self.manager.config

    @property
    def target(self) -> Target:
        """Retrieve the target object for this session"""

        try:
            # Find target object
            return next(t for t in self.db.root.targets if t.guid == self.hash)
        except StopIteration:
            return None

    def register_new_host(self):
        """Register a new host in the database. This assumes the
        hash has already been stored in ``self.hash``"""

        # Create a new target descriptor
        target = Target()
        target.guid = self.hash
        target.public_address = (self.platform.channel.host, self.platform.channel.port)
        target.platform = self.platform.name

        # Add the target to the database
        self.db.transaction_manager.begin()
        self.db.root.targets.append(target)
        self.db.transaction_manager.commit()

        self.log("registered new host w/ db")

    def current_user(self) -> pwncat.facts.User:
        """Retrieve the current user object"""

        return self.find_user(uid=self.platform.getuid())

    def find_user(self, uid=None, name=None):
        """Locate a user object by name or ID"""

        for user in self.run("enumerate.gather", progress=False, types=["user"]):
            if (uid is None or user.id == uid) and (name is None or user.name == name):
                return user

    def iter_users(self):
        """Iterate over the users for the target"""

        yield from self.run("enumerate.gather", progress=False, types=["user"])

    def find_group(self, gid=None, name=None):
        """Locate a user object by name or ID"""

        for group in self.run("enumerate.gather", progress=False, types=["group"]):
            if (gid is None or group.id == gid) and (
                name is None or group.name == name
            ):
                return group

    def iter_groups(self, members: Optional[List[Union[str, int]]] = None):
        """Iterate over groups for the target"""

        for group in self.run("enumerate.gather", progress=False, types=["group"]):
            if members is None or any(m in group.members for m in members):
                yield group

    def register_fact(
        self,
        fact: "pwncat.db.Fact",
        scope: Scope = Scope.HOST,
        commit: bool = False,
    ):
        """Register a fact with this session's target. This is useful when
        a fact is generated during execution of a command or module, but is
        not associated with a specific enumeration module. It can still be
        queried with the base `enumerate` module by it's type."""

        if scope is Scope.HOST and fact not in self.target.facts:
            self.target.facts.append(fact)
            if commit:
                self.db.transaction_manager.commit()
        elif scope is Scope.SESSION and fact not in self.facts:
            self.facts.append(fact)

    def run(self, module: str, **kwargs):
        """Run a module on this session"""

        module_name = module
        module = self.manager.modules.get(module_name)
        if module is None:
            module = self.manager.modules.get(self.platform.name + "." + module_name)
        if module is None:
            module = self.manager.modules.get("agnostic." + module_name)
        if module is None:
            raise pwncat.modules.ModuleNotFound(module_name)

        if module.PLATFORM is not None and type(self.platform) not in module.PLATFORM:
            raise pwncat.modules.IncorrectPlatformError(module_name)

        return module.run(self, **kwargs)

    def find_module(self, pattern: str, base=None, exact: bool = False):
        """Locate a module by a glob pattern. This is an generator
        which may yield multiple modules that match the pattern and
        base class."""

        if base is None:
            base = pwncat.modules.BaseModule

        for name, module in self.manager.modules.items():
            if (
                module.PLATFORM is not None
                and type(self.platform) not in module.PLATFORM
            ):
                continue
            if not issubclass(type(module), base):
                continue
            if not exact:
                if (
                    fnmatch.fnmatch(name, pattern)
                    or fnmatch.fnmatch(name, f"agnostic.{pattern}")
                    or fnmatch.fnmatch(name, f"{self.platform.name}.{pattern}")
                ):
                    yield module
            elif exact:
                if (
                    name == pattern
                    or name == f"agnostic.{pattern}"
                    or name == f"{self.platform.name}.{pattern}"
                ):
                    yield module

    def log(self, *args, **kwargs):
        """Log to the console. This utilizes the active sessions
        progress instance to log without messing up progress output
        from other sessions, if we aren't active."""

        self.manager.log(f"{self.platform}:", *args, **kwargs)

    def print(self, *args, **kwargs):
        """Log to the console. This utilizes the active sessions
        progress instance to log without messing up progress output
        from other sessions, if we aren't active."""

        self.manager.print(f"{self.platform}:", *args, **kwargs)

    @contextlib.contextmanager
    def task(self, *args, **kwargs):
        """Get a new task in this session's progress instance"""

        # Ensure the variable exists even if an exception happens
        # prior to task creation
        task = None
        started = self._progress is not None  # ._started

        if "status" not in kwargs:
            kwargs["status"] = "..."

        kwargs["platform"] = str(self.platform)

        try:
            # Ensure this bar is started if we are the selected
            # target.
            if not started:
                self._progress = rich.progress.Progress(
                    "{task.fields[platform]}",
                    "•",
                    "{task.description}",
                    "•",
                    "{task.fields[status]}",
                    transient=True,
                    console=console,
                )
                self._progress.start()

            # Create the new task
            task = self._progress.add_task(*args, **kwargs)
            yield task
        finally:
            # If the progress wasn't started when we entered,
            # ensure it is stopped before we leave. This allows
            # nested tasks.
            if not started:
                self._progress.stop()
                if task is not None:
                    self._progress.remove_task(task)
                self._progress = None
            elif task is not None:
                self._progress.remove_task(task)

    def update_task(self, task, *args, **kwargs):
        """Update an active task"""

        self._progress.update(task, *args, **kwargs)

    def died(self):

        if self.id not in self.manager.sessions:
            return

        del self.manager.sessions[self.id]

        if self.manager.target == self:
            self.manager.target = None

    def close(self):
        """Close the session and remove from manager tracking"""

        tampers = self.run("enumerate", types=["tamper"], progress=False)
        implants = self.run("enumerate", types=["implant.*"], progress=False)

        if tampers:
            self.log("Leaving behind the following tampers:")
            for tamper in tampers:
                self.log(f"  - {tamper.title(self)}")

        if implants:
            self.log("Leaving behind the following implants:")
            for implant in implants:
                self.log(f"  - {implant.title(self)}")

        # Unwrap all layers in the session
        while self.layers:
            self.layers.pop()(self)

        try:
            self.platform.exit()
            self.platform.channel.close()
        except (PlatformError, ChannelError) as exc:
            self.log(
                f"[yellow]warning[/yellow]: unexpected exception while closing: {exc}"
            )

        self.died()

    def __enter__(self):

        return self

    def __exit__(self, _, __, ___):

        self.close()


class Manager:
    """
    ``pwncat`` manager which is responsible for creating channels,
    and sessions, managing the database sessions. It provides the
    factory functions for generating platforms, channels, database
    sessions, and executing modules.
    """

    def __init__(self, config: str = None):
        self.config = Config()
        self.session_id = 0  # start with 0-indexed session IDs
        self.sessions: Dict[int, Session] = {}
        self.modules: Dict[str, pwncat.modules.BaseModule] = {}
        self._target = None
        self.parser = CommandParser(self)
        self.interactive_running = False
        self.db: ZODB.DB = None
        self.listeners: List[Listener] = []

        # This is needed because pwntools captures the terminal...
        # there's no way officially to undo it, so this is a nasty
        # hack. You can't use pwntools output after creating a manager.
        self._patch_pwntools()

        # Load standard modules
        self.load_modules(*pwncat.modules.__path__)

        # Get our data directory
        data_home = os.environ.get("XDG_DATA_HOME", "~/.local/share")
        if not data_home:
            data_home = "~/.local/share"

        # Expand the user path
        data_home = os.path.expanduser(os.path.join(data_home, "pwncat"))

        # Find modules directory
        modules_dir = os.path.join(data_home, "modules")

        # Load local modules if they exist
        if os.path.isdir(modules_dir):
            self.load_modules(modules_dir)

        # Load global configuration script, if available
        try:
            with open("/etc/pwncat/pwncatrc") as filp:
                self.parser.eval(filp.read(), "/etc/pwncat/pwncatrc")
        except (FileNotFoundError, PermissionError):
            pass

        # Load user configuration script
        user_rc = os.path.join(data_home, "pwncatrc")
        try:
            with open(user_rc) as filp:
                self.parser.eval(filp.read(), user_rc)
        except (FileNotFoundError, PermissionError):
            pass

        # Load local configuration script
        if isinstance(config, str):
            with open(config) as filp:
                self.parser.eval(filp.read(), config)
        elif config is not None:
            self.parser.eval(config.read(), getattr(config, "name", "fileobj"))
            config.close()
        else:
            try:
                # If no config is specified, attempt to load `./pwncatrc`
                # but don't fail if it doesn't exist.
                with open("./pwncatrc") as filp:
                    self.parser.eval(filp.read(), "./pwncatrc")
            except (FileNotFoundError, PermissionError):
                pass

        if self.db is None:
            self.open_database()

    def __enter__(self):
        """Begin manager context tracking"""

        return self

    def __exit__(self, _, __, ___):
        """Ensure all sessions are closed"""

        # Retrieve the existing session IDs list
        session_ids = list(self.sessions.keys())

        # Close each session based on its ``session_id``
        for session_id in session_ids:
            self.sessions[session_id].close()

    def open_database(self):
        """Create the internal engine and session builder
        for this manager based on the configured database"""

        if self.sessions and self.db is not None:
            raise RuntimeError("cannot change database after sessions are established")

        # Connect/open the database
        factory_class, factory_args = zodburi.resolve_uri(self.config["db"])
        storage = factory_class()
        self.db = ZODB.DB(storage, **factory_args)

        conn = self.db.open()

        if not hasattr(conn.root, "targets"):
            conn.root.targets = persistent.list.PersistentList()

        if not hasattr(conn.root, "history"):
            conn.root.history = persistent.list.PersistentList()

        conn.transaction_manager.commit()
        conn.close()

        # Rebuild the command parser now that the database is available
        self.parser = CommandParser(self)

    def create_db_session(self):
        """Create a new SQLAlchemy database session and return it"""

        # Initialize a fallback database if needed
        if self.db is None:
            self.config.set("db", "memory://", glob=True)
            self.open_database()

        return self.db.open()

    def load_modules(self, *paths):
        """Dynamically load modules from the specified paths

        If a module has the same name as an already loaded module, it will
        take it's place in the module list. This includes built-in modules.
        """

        for loader, module_name, _ in pkgutil.walk_packages(
            paths, prefix="pwncat.modules."
        ):

            # Why is this check *not* part of pkgutil??????? D:<
            if module_name not in sys.modules:
                module = loader.find_module(module_name).load_module(module_name)
            else:
                module = sys.modules[module_name]

            if getattr(module, "Module", None) is None:
                continue

            # Create an instance of this module
            module_name = module_name.split("pwncat.modules.")[1]
            self.modules[module_name] = module.Module()

            # Store it's name so we know it later
            setattr(self.modules[module_name], "name", module_name)

    def log(self, *args, **kwargs):
        """Output a log entry"""

        if self.target is not None and self.target._progress is not None:
            self.target._progress.log(*args, **kwargs)
        else:
            console.log(*args, **kwargs)

    def print(self, *args, **kwargs):

        if self.target is not None and self.target._progress is not None:
            self.target._progress.print(*args, **kwargs)
        else:
            console.print(*args, **kwargs)

    @property
    def target(self) -> Session:
        """Retrieve the currently focused target"""
        return self._target

    @target.setter
    def target(self, value: Session):
        if value is not None and value not in self.sessions.values():
            raise ValueError("invalid target")
        self._target = value

    def _patch_pwntools(self):
        """This method patches stdout and stdin and sys.exchook
        back to their original contents temporarily in order to
        interact properly with pwntools. You must complete all
        pwntools progress items before calling this. It attempts to
        remove all the hooks placed into stdio by pwntools."""

        pwnlib = None

        # We only run this if pwnlib is loaded
        if "pwnlib" in sys.modules:
            pwnlib = sys.modules["pwnlib"]

        if pwnlib is None or not pwnlib.term.term_mode:
            return

        sys.stdout = sys.stdout._fd
        sys.stdin = sys.stdin._fd
        # I don't know how to get the old hook back...
        sys.excepthook = lambda _, __, ___: None
        pwnlib.term.term_mode = False

    def interactive(self):
        """Start interactive prompt"""

        self.interactive_running = True

        # This is required to ensure multi-byte key-sequences are read
        # properly
        sys.stdin
        sys.stdin = TextIOWrapper(
            os.fdopen(sys.stdin.fileno(), "br", buffering=0),
            write_through=True,
            line_buffering=True,
        )

        while self.interactive_running:

            try:

                # This is it's own main loop that will continue until
                # it catches a C-d sequence.
                try:
                    self.parser.run()
                except InteractiveExit:

                    if self.sessions and not confirm(
                        "There are active sessions. Are you sure?"
                    ):
                        continue

                    self.log("closing interactive prompt")
                    break

                # We can't enter raw mode without a session
                if self.target is None:
                    self.log("no active session, returning to local prompt")
                    continue

                interactive_complete = threading.Event()
                output_thread = None

                def output_thread_main(
                    target: Session, exception_queue: queue.SimpleQueue
                ):

                    while not interactive_complete.is_set():
                        try:
                            data = target.platform.channel.recv(4096)

                            if data != b"" and data is not None:
                                data = target.platform.process_output(data)
                                sys.stdout.buffer.write(data)
                                sys.stdout.buffer.flush()
                            else:
                                interactive_complete.wait(timeout=0.1)

                        except ChannelError as exc:
                            exception_queue.put(exc)
                            interactive_complete.set()
                            # This is a hack to get the interactive loop out of a blocking
                            # read call. The interactive loop will receive a KeyboardInterrupt
                            os.kill(os.getpid(), signal.SIGINT)
                        except RawModeExit:
                            interactive_complete.set()
                            os.kill(os.getpid(), signal.SIGINT)

                try:
                    self.target.platform.interactive = True

                    exception_queue = queue.Queue(maxsize=1)
                    output_thread = threading.Thread(
                        target=output_thread_main, args=[self.target, exception_queue]
                    )
                    output_thread.start()

                    try:
                        self.target.platform.interactive_loop(interactive_complete)
                    except RawModeExit:
                        interactive_complete.set()

                    try:
                        raise exception_queue.get(block=False)
                    except queue.Empty:
                        pass

                    self.target.platform.interactive = False
                except ChannelClosed:
                    self.log(
                        f"[yellow]warning[/yellow]: {self.target.platform}: connection reset"
                    )
                    self.target.died()
                finally:
                    interactive_complete.set()
                    if output_thread is not None:
                        output_thread.join()
                        output_thread.join()
            except:  # noqa: E722
                # We don't want to die because of an uncaught exception, but
                # at least let the user know something happened. This should
                # probably be configurable somewhere.
                pwncat.util.console.print_exception()

    def create_listener(
        self,
        protocol: str,
        host: str,
        port: int,
        platform: Optional[str] = None,
        ssl: bool = False,
        ssl_cert: Optional[str] = None,
        ssl_key: Optional[str] = None,
        count: Optional[int] = None,
        established: Optional[Callable[[Session], bool]] = None,
    ) -> Listener:
        """
        Create and start a new background listener which will wait for connections from
        victims and optionally automatically establish sessions. If no platform name is
        provided, new ``Channel`` objects will be created and can be initialized by
        iterating over them with ``listener.iter_channels`` and initialized with
        ``listener.bootstrap_session``. If ``ssl`` is true, the socket will be wrapped in
        an SSL context. The protocol is normally ``socket``, but can be any channel
        protocol which supports a ``client`` parameter holding a socket object.

        :param protocol: the name of the channel protocol to use (default: socket)
        :type protocol: str
        :param host: the host address on which to bind
        :type host: str
        :param port: the port on which to listen
        :type port: int
        :param platform: the platform to use when automatically establishing sessions or None
        :type platform: Optional[str]
        :param ssl: whether to wrap the listener in an SSL context (default: false)
        :type ssl: bool
        :param ssl_cert: the SSL PEM certificate path
        :type ssl_cert: Optional[str]
        :param ssl_key: the SSL PEM key path
        :type ssl_key: Optional[str]
        :param count: the number of sessions to establish before automatically stopping the listener
        :type count: Optional[int]
        :param established: a callback for when new sessions are established; returning false will
                            immediately disconnect the new session.
        :type established: Optional[Callback[[Session], bool]]
        """

        listener = Listener(
            manager=self,
            address=(host, port),
            protocol=protocol,
            platform=platform,
            count=count,
            established=established,
            ssl=ssl,
            ssl_cert=ssl_cert,
            ssl_key=ssl_key,
        )

        listener.start()

        self.listeners.append(listener)

        return listener

    def create_session(self, platform: str, channel: Channel = None, **kwargs):
        r"""
        Create a new session from a new or existing channel. The platform specified
        should be the name registered name (e.g. ``linux``) of a platform class. If
        no existing channel is provided, the keyword arguments are used to construct
        a new channel.

        :param platform: name of the platform to use
        :type platform: str
        :param channel: A pre-constructed channel (default: None)
        :type channel: Optional[Channel]
        :param \*\*kwargs: keyword arguments for constructing a new channel
        :rtype: Session
        :raises:
            ChannelError: there was an error while constructing the new channel
            PlatformError: construction of a platform around the channel failed
        """

        session = Session(self, platform, channel, **kwargs)

        # Increment the ``session_id`` variable upon adding a new session
        # Session constructor will automatically grab the current
        # ``session_id`` from the ``manager`` object passed as the first argument

        self.session_id += 1

        return session

    def find_session_by_channel(self, channel: Channel):
        """
        Locate a session by it's channel object. This is mainly used when a ChannelError
        is raised in order to locate the misbehaving session object from the exception
        data.

        :param channel: the channel you are looking for
        :type channel: Channel
        :rtype: Session
        """

        for session in self.sessions.values():
            if session.platform.channel is channel:
                return session

    def _process_input(self, data: bytes, has_prefix: bool):
        """Process stdin data from the user in raw mode"""

        for byte in data:
            byte = bytes([byte])

            if has_prefix:
                # Reset prefix flag
                has_prefix = False

                if byte == self.config["prefix"].value:
                    self.target.platform.channel.send(byte)
                else:
                    try:
                        binding = self.config.binding(byte)
                    except KeyError:
                        continue

                    if binding.strip().startswith("pass"):
                        self.target.platform.channel.send(byte)
                        binding = binding.lstrip("pass")
                    else:
                        self.target.platform.interactive = False
                        # pwncat.util.restore_terminal(term_state)

                        sys.stdout.write("\n")

                        self.parser.eval(binding, "<binding>")

                        self.target.platform.channel.send(b"\n")

                        self.target.platform.interactive = True
                        # pwncat.util.enter_raw_mode()
            elif byte == self.config["prefix"].value:
                has_prefix = True
            elif data == pwncat.config.KeyType("c-d").value:
                raise RawModeExit
            else:
                self.target.platform.channel.send(byte)

        return has_prefix
