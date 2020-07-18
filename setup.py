#!/usr/bin/env python

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import shutil, os, stat
import binascii

dependencies = [
    "colorama==0.4.3",
    "wcwidth==0.1.9",
    "netifaces==0.10.9",
    "pygments==2.6.1",
    "base64io",
    "commentjson",
    "requests",
    "prompt-toolkit",
    "sqlalchemy",
    "paramiko",
    "pytablewriter",
    "rich",
    "pycryptodome",
]

dependency_links = [
    "https://github.com/calebstewart/paramiko/tarball/master#egg=paramiko",
    "https://github.com/JohnHammond/base64io-python/tarball/master#egg=base64io",
]

# Setup
setup(
    name="pwncat",
    version="0.3.1",
    description="A fancy reverse and bind shell handler",
    author="Caleb Stewart",
    url="https://gitlab.com/calebstewart/pwncat",
    packages=find_packages(),
    package_data={"pwncat": ["data/*"]},
    entry_points={"console_scripts": ["pwncat=pwncat.__main__:main"]},
    data_files=[],
    install_requires=dependencies,
    dependency_links=dependency_links,
)
