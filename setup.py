#!/usr/bin/env python

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import shutil, os, stat
import binascii

dependencies = [
    "prompt-toolkit",
    "wcwidth",
    "colorama"
]

dependency_links = []

# Setup
setup(
    name="pwncat",
    version="0.1",
    description="A fancy reverse and bind shell handler",
    author="Caleb Stewart",
    url="https://gitlab.com/calebstewart/pwncat",
    packages=find_packages(),
    package_data={},
    entry_points={"console_scripts": ["pwncat=pwncat.__main__:main"]},
    data_files=[],
    install_requires=dependencies,
    dependency_links=dependency_links,
)
