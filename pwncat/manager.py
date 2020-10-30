#!/usr/bin/env python3
from typing import List, Dict, Union, Optional
import contextlib
import pkgutil
import fnmatch
import os

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
import rich.progress

import pwncat.db
import pwncat.modules
from pwncat.util import console
from pwncat.platform import Platform
from pwncat.channel import Channel
from pwncat.config import Config
from pwncat.commands import CommandParser


class Session:
    """ Wraps a channel and platform and tracks configuration and
    database access per session """

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
            self.host = session.query(pwncat.db.Host).filter_by(hash=self.hash).first()
        if self.host is None:
            self.register_new_host()
        else:
            self.log("loaded known host from db")

    @property
    def config(self):
        """ Get the configuration object for this manager. This
        is simply a wrapper for session.manager.config to make
        accessing configuration a little easier. """
        return self.manager.config

    def register_new_host(self):
        """ Register a new host in the database. This assumes the
        hash has already been stored in ``self.hash`` """

        # Create a new host object and add it to the database
        self.host = pwncat.db.Host(hash=self.hash, platform=self.platform.name)

        with self.db as session:
            session.add(self.host)

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

    def find_module(self, pattern: str, base=None):
        """ Locate a module by a glob pattern. This is an generator
        which may yield multiple modules that match the pattern and
        base class. """

        if base is None:
            base = pwncat.modules.BaseModule

        for name, module in self.manager.modules.items():
            if (
                module.PLATFORM is not None
                and type(self.platform) not in module.PLATFORM
            ):
                continue
            if fnmatch.fnmatch(name, pattern) and isinstance(module, base):
                yield module

    def log(self, *args, **kwargs):
        """ Log to the console. This utilizes the active sessions
        progress instance to log without messing up progress output
        from other sessions, if we aren't active. """

        self.manager.log(f"{self.platform}:", *args, **kwargs)

    @property
    @contextlib.contextmanager
    def db(self):
        """ Retrieve a database session

        I'm not sure if this is the best way to handle database sessions.

        """

        new_session = self._db_session is None

        try:
            if new_session:
                self._db_session = self.manager.create_db_session()
            yield self._db_session
        finally:
            if new_session and self._db_session is not None:
                session = self._db_session
                self._db_session = None
                session.close()

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
        try:
            with open(config) as filp:
                self.parser.eval(filp.read(), config)
        except (FileNotFoundError, PermissionError):
            pass

    def open_database(self):
        """ Create the internal engine and session builder
        for this manager based on the configured database """

        if self.sessions and self.engine is not None:
            raise RuntimeError("cannot change database after sessions are established")

        self.engine = create_engine(self.config["db"])
        pwncat.db.Base.metadata.create_all(self.engine)
        self.SessionBuilder = sessionmaker(bind=self.engine)

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
        """ Dynamically load modules from the specified paths

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

    @property
    def target(self) -> Session:
        """ Retrieve the currently focused target """
        return self._target

    @target.setter
    def target(self, value: Session):
        if value not in self.sessions:
            raise ValueError("invalid target")
        self._target = value

    def interactive(self):
        """ Start interactive prompt """

        # This needs to be a full main loop with raw-mode support
        # eventually, but I want to get the command parser working for
        # now. The raw mode is the easy part.
        self.parser.run()

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
