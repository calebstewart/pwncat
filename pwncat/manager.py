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
from pwncat.platform import Platform
from pwncat.channel import Channel


class Session:
    """ Wraps a channel and platform and tracks configuration and
    database access per session """

    def __init__(
        self,
        manager,
        platform: Union[str, Platform],
        channel: Optional[Channel] = None,
        **kwargs
    ):
        self.manager = manager
        self._progress = rich.progress.Progress(
            str(platform),
            "•",
            "{task.description}",
            "•",
            "{task.fields[status]}",
            transient=True,
        )
        self.config = {}
        self.background = None
        self._db_session = None

        if isinstance(platform, Platform):
            self.platform = platform
        else:
            if channel is None:
                channel = pwncat.channel.create(**kwargs)

            self.platform = pwncat.platform.find(platform)(
                self, channel, self.get("log")
            )

        # Initialize the host reference
        self.hash = self.platform.get_host_hash()
        self.host = self.db.query(pwncat.db.Host).filter_by(hash=self.hash).first()
        if self.host is None:
            self.register_new_host()

    def register_new_host(self):
        """ Register a new host in the database. This assumes the
        hash has already been stored in ``self.hash`` """

        # Create a new host object and add it to the database
        self.host = pwncat.db.Host(hash=self.hash, platform=self.platform.name)
        self.db.add(self.host)

    def get(self, name, default=None):
        """ Get the value of a configuration item """

        if name not in self.config:
            return self.manager.get(name, default)

        return self.config[name]

    def set(self, name, value):
        """ Set the value of a configuration item """

        self.config[name] = value

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

        self.manager.target.progress.log(*args, **kwargs)

    @property
    def db(self):
        """ Retrieve a database session

        I'm not sure if this is the best way to handle database sessions.

        """

        new_session = self._db_session is None

        try:
            if new_session:
                self._db_session = self.manager.create_db_session()
            return self._db_session
        finally:
            if new_session:
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
            return task
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

    def __init__(self, config: str):
        self.config = {}
        self.sessions: List[Session] = []
        self.modules: Dict[str, pwncat.modules.BaseModule] = {}
        self.engine = None
        self.SessionBuilder = None

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

    def create_db_session(self):
        """ Create a new SQLAlchemy database session and return it """

        # Initialize a fallback database if needed
        if self.engine is None:
            self.set("db", "sqlite:///:memory:")

        return self.SessionBuilder()

    def set(self, key, value):
        """ Set a configuration item in the global manager """

        self.config[key] = value

        if key == "db":
            # This is dangerous for background modules
            if self.engine is not None:
                self.engine.dispose()
            self.engine = create_engine(value)
            pwncat.db.Base.metadata.create_all(self.engine)
            self.SessionBuilder = sessionmaker(bind=self.engine)

    def get(self, key, default=None):
        """ Retrieve the value of a configuration item """

        return self.config.get(key, default)

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

    @property
    def target(self) -> Session:
        """ Retrieve the currently focused target """
        return self._target

    @target.setter
    def target(self, value: Session):
        if value not in self.sessions:
            raise ValueError("invalid target")
        self._target = value

    def run(self, module: str, **kwargs):
        """ Execute a module on the currently active target """

    def find_module(self, pattern: str):
        """ Enumerate modules applicable to the current target """

    def interactive(self):
        """ Start interactive prompt """

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
        self.sessions.append(session)

        return session
