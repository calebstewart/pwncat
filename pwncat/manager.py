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
import sys
import fnmatch
import pkgutil
import threading
import contextlib
from io import TextIOWrapper
from typing import Dict, List, Union, Optional

import ZODB
import zodburi
import rich.progress
import persistent.list
from prompt_toolkit.shortcuts import confirm

import pwncat.db
import pwncat.facts
import pwncat.modules
import pwncat.modules.enumerate
from pwncat.util import RawModeExit, console
from pwncat.config import Config
from pwncat.target import Target
from pwncat.channel import Channel, ChannelClosed
from pwncat.commands import CommandParser
from pwncat.platform import Platform


class InteractiveExit(Exception):
    """Indicates we should exit the interactive terminal"""


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
        **kwargs,
    ):
        self.manager = manager
        self.background = None
        self._db_session = None
        self.db = manager.db.open()
        self.module_depth = 0
        self.showing_progress = True
        self.layers = []

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
        self.manager.sessions.append(self)
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

    def register_fact(self, fact: "pwncat.db.Fact"):
        """Register a fact with this session's target. This is useful when
        a fact is generated during execution of a command or module, but is
        not associated with a specific enumeration module. It can still be
        queried with the base `enumerate` module by it's type."""

        if fact not in self.target.facts:
            self.target.facts.append(fact)
            self.db.transaction_manager.commit()

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

        if self not in self.manager.sessions:
            return

        self.manager.sessions.remove(self)

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

        self.platform.exit()

        self.platform.channel.close()

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
        self.sessions: List[Session] = []
        self.modules: Dict[str, pwncat.modules.BaseModule] = {}
        self._target = None
        self.parser = CommandParser(self)
        self.interactive_running = False
        self.db: ZODB.DB = None

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

        while self.sessions:
            self.sessions[0].close()

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
        if value is not None and value not in self.sessions:
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

            self.target.platform.interactive = True

            interactive_complete = threading.Event()

            def output_thread_main():

                while not interactive_complete.is_set():

                    data = self.target.platform.channel.recv(4096)

                    if data != b"" and data is not None:
                        try:
                            data = self.target.platform.process_output(data)
                            sys.stdout.buffer.write(data)
                            sys.stdout.buffer.flush()
                        except RawModeExit:
                            interactive_complete.set()
                    else:
                        interactive_complete.wait(timeout=0.1)

            output_thread = threading.Thread(target=output_thread_main)
            output_thread.start()

            channel_closed = False

            try:
                self.target.platform.interactive_loop(interactive_complete)
            except RawModeExit:
                pass
            except ChannelClosed:
                channel_closed = True
                self.log(
                    f"[yellow]warning[/yellow]: {self.target.platform}: connection reset"
                )
            except Exception:
                pwncat.util.console.print_exception()

            # Trigger thread to exit
            interactive_complete.set()
            output_thread.join()

            # Exit interactive mode
            if channel_closed:
                self.target.died()
            else:
                self.target.platform.interactive = False

    def create_session(self, platform: str, channel: Channel = None, **kwargs):
        """
        Open a new session from a new or existing platform. If the platform
        is a string, a new platform is created using ``create_platform`` and
        a session is built around the platform. In that case, the arguments
        are the same as for ``create_platform``.

        A new Session object is returned which contains the created or
        specified platform.
        """

        session = Session(self, platform, channel, **kwargs)
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
