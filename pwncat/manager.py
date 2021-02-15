#!/usr/bin/env python3
from typing import List, Dict, Union, Optional
from prompt_toolkit.shortcuts import confirm
from io import TextIOWrapper
import threading
import contextlib
import pkgutil
import fnmatch
import selectors
import sys
import os

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import rich.progress

import pwncat.db
import pwncat.modules
from pwncat.util import console, RawModeExit
from pwncat.platform import Platform
from pwncat.channel import Channel, ChannelClosed
from pwncat.config import Config
from pwncat.commands import CommandParser


class InteractiveExit(Exception):
    """ Indicates we should exit the interactive terminal """


class Session:
    """Wraps a channel and platform and tracks configuration and
    database access per session"""

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

        # If necessary, build a new platform object
        if isinstance(platform, Platform):
            self.platform = platform
        else:
            # If necessary, build a new channel
            if channel is None:
                channel = pwncat.channel.create(**kwargs)

            self.platform = pwncat.platform.find(platform)(
                self, channel, self.config.get("log", None)
            )

        self._progress = rich.progress.Progress(
            str(self.platform),
            "•",
            "{task.description}",
            "•",
            "{task.fields[status]}",
            transient=True,
        )

        # Register this session with the manager
        self.manager.sessions.append(self)
        self.manager.target = self

        # Initialize the host reference
        self.hash = self.platform.get_host_hash()
        with self.db as session:
            host = session.query(pwncat.db.Host).filter_by(hash=self.hash).first()
        if host is None:
            self.register_new_host()
        else:
            self.host = host.id
            self.log("loaded known host from db")

        self.platform.get_pty()

    @property
    def config(self):
        """Get the configuration object for this manager. This
        is simply a wrapper for session.manager.config to make
        accessing configuration a little easier."""
        return self.manager.config

    def register_new_host(self):
        """Register a new host in the database. This assumes the
        hash has already been stored in ``self.hash``"""

        # Create a new host object and add it to the database
        host = pwncat.db.Host(hash=self.hash, platform=self.platform.name)

        with self.db as session:
            session.add(host)
            session.commit()

        self.host = host.id

        self.log("registered new host w/ db")

    def run(self, module: str, **kwargs):
        """ Run a module on this session """

        if module not in self.manager.modules:
            raise pwncat.modules.ModuleNotFound(module)

        if (
            self.manager.modules[module].PLATFORM is not None
            and type(self.platform) not in self.manager.modules[module].PLATFORM
        ):
            raise pwncat.modules.IncorrectPlatformError(module)

        return self.manager.modules[module].run(self, **kwargs)

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
            if (
                not exact
                and fnmatch.fnmatch(name, pattern)
                and isinstance(module, base)
            ):
                yield module
            elif exact and name == pattern and isinstance(module, base):
                yield module

    def log(self, *args, **kwargs):
        """Log to the console. This utilizes the active sessions
        progress instance to log without messing up progress output
        from other sessions, if we aren't active."""

        self.manager.log(f"{self.platform}:", *args, **kwargs)

    @property
    @contextlib.contextmanager
    def db(self):
        """Retrieve a database session

        I'm not sure if this is the best way to handle database sessions.

        """

        try:
            if self._db_session is None:
                self._db_session = self.manager.create_db_session()
            yield self._db_session
        finally:
            try:
                self._db_session.commit()
            except:
                pass

    @contextlib.contextmanager
    def task(self, *args, **kwargs):
        """ Get a new task in this session's progress instance """

        # Ensure the variable exists even if an exception happens
        # prior to task creation
        task = None
        started = self._progress._started

        if "status" not in kwargs:
            kwargs["status"] = "..."

        try:
            # Ensure this bar is started if we are the selected
            # target.
            if self.manager.target == self:
                self._progress.start()
            # Create the new task
            task = self._progress.add_task(*args, **kwargs)
            yield task
        finally:
            if task is not None:
                # Delete the task
                self._progress.remove_task(task)
            # If the progress wasn't started when we entered,
            # ensure it is stopped before we leave. This allows
            # nested tasks.
            if not started:
                self._progress.stop()

    def update_task(self, task, *args, **kwargs):
        """ Update an active task """

        self._progress.update(task, *args, **kwargs)

    def died(self):

        if self not in self.manager.sessions:
            return

        self.manager.sessions.remove(self)

        if self.manager.target == self:
            self.manager.target = None


class Manager:
    """
    ``pwncat`` manager which is responsible for creating channels,
    and sessions, managing the database sessions. It provides the
    factory functions for generating platforms, channels, database
    sessions, and executing modules.
    """

    def __init__(self, config: str = "./pwncatrc"):
        self.config = Config()
        self.sessions: List[Session] = []
        self.modules: Dict[str, pwncat.modules.BaseModule] = {}
        self.engine = None
        self.SessionBuilder = None
        self._target = None
        self.parser = CommandParser(self)
        self.interactive_running = False

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
            try:
                with open(config) as filp:
                    self.parser.eval(filp.read(), config)
            except (FileNotFoundError, PermissionError):
                pass
        elif config is not None:
            self.parser.eval(config.read(), config.name)
            config.close()

    def open_database(self):
        """Create the internal engine and session builder
        for this manager based on the configured database"""

        if self.sessions and self.engine is not None:
            raise RuntimeError("cannot change database after sessions are established")

        self.engine = create_engine(self.config["db"])
        pwncat.db.Base.metadata.create_all(self.engine)
        self.SessionBuilder = sessionmaker(bind=self.engine, expire_on_commit=False)
        self.parser = CommandParser(self)

    def create_db_session(self):
        """ Create a new SQLAlchemy database session and return it """

        # Initialize a fallback database if needed
        if self.engine is None:
            self.config.set("db", "sqlite:///:memory:", glob=True)
            self.open_database()

        return self.SessionBuilder()

    @contextlib.contextmanager
    def new_db_session(self):
        """ Track a database session in a context manager """

        session = None

        try:
            session = self.create_db_session()
            yield session
        finally:
            pass

    def load_modules(self, *paths):
        """Dynamically load modules from the specified paths

        If a module has the same name as an already loaded module, it will
        take it's place in the module list. This includes built-in modules.
        """

        for loader, module_name, _ in pkgutil.walk_packages(
            paths, prefix="pwncat.modules."
        ):
            module = loader.find_module(module_name).load_module(module_name)

            if getattr(module, "Module", None) is None:
                continue

            # Create an instance of this module
            module_name = module_name.split("pwncat.modules.")[1]
            self.modules[module_name] = module.Module()

            # Store it's name so we know it later
            setattr(self.modules[module_name], "name", module_name)

    def log(self, *args, **kwargs):
        """ Output a log entry """

        if self.target is not None:
            self.target._progress.log(*args, **kwargs)
        else:
            console.log(*args, **kwargs)

    def print(self, *args, **kwargs):

        if self.target is not None:
            self.target._progress.print(*args, **kwargs)
        else:
            console.print(*args, **kwargs)

    @property
    def target(self) -> Session:
        """ Retrieve the currently focused target """
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
        """ Start interactive prompt """

        self.interactive_running = True

        # This is required to ensure multi-byte key-sequences are read
        # properly
        old_stdin = sys.stdin
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

            # NOTE - I don't like the selectors solution for async stream IO
            # Currently, we utilize the built-in selectors module.
            # This module depends on the epoll/select interface on Linux.
            # This requires that the challels are file-objects (have a fileno method)
            # I don't like this. I may switch to an asyncio-based wrapper in
            # the future, to alleviate requirements on channel implementations
            # but I'm not sure how to implement it right now.
            # selector = selectors.DefaultSelector()
            # selector.register(sys.stdin, selectors.EVENT_READ, None)
            # selector.register(self.target.platform.channel, selectors.EVENT_READ, None)

            # Make the local terminal enter a raw state for
            # direct interaction with the remote shell
            # term_state = pwncat.util.enter_raw_mode()

            # pwncat.util.push_term_state()
            # pwncat.util.enter_raw_mode()

            self.target.platform.interactive = True

            interactive_complete = threading.Event()

            def output_thread_main():

                while not interactive_complete.is_set():

                    data = self.target.platform.channel.recv(4096)

                    if data != b"" and data != None:
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

            has_prefix = False
            channel_closed = False

            try:
                self.target.platform.interactive_loop()
                # while not interactive_complete.is_set():
                #     data = sys.stdin.buffer.read(64)
                #     has_prefix = self._process_input(data, has_prefix)
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

            # pwncat.util.pop_term_state()

            # Exit interactive mode
            if channel_closed:
                self.target.died()
            else:
                self.target.platform.interactive = False

            # try:
            #     # We do this until the user pressed <prefix>+C-d or
            #     # until the connection dies. Afterwards, we go back to
            #     # a local prompt.
            #     done = False
            #     has_prefix = False
            #     while not done:
            #         for k, _ in selector.select():
            #             if k.fileobj is sys.stdin:
            #                 data = sys.stdin.buffer.read(64)
            #                 has_prefix = self._process_input(data, has_prefix)
            #             else:
            #                 data = self.target.platform.channel.recv(4096)
            #                 self.target.platform.process_output(data)
            #                 sys.stdout.buffer.write(data)
            # except RawModeExit:
            #     self.target.platform.interactive = False
            # except ChannelClosed:
            #     self.target.platform.interactive = False
            #     self.log(
            #         f"[yellow]warning[/yellow]: {self.target.platform}: connection reset"
            #     )
            #     self.target.died()
            # except Exception:
            #     self.target.platform.interactive = False
            #     pwncat.util.console.print_exception()

            # if self.target is not None and self.target.platform.interactive:
            #     self.target.platform.interactive = False

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
        """ Process stdin data from the user in raw mode """

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
