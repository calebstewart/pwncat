#!/usr/bin/env python

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import shutil, os, stat
import binascii

# Read the requirements
with open("requirements.txt") as filp:
    dependencies = [
        line.strip() for line in filp.readlines() if not line.startswith("#")
    ]

# Build dependency links for entries that need them
# This works for "git+https://github.com/user/package" refs
dependency_links = [dep for dep in dependencies if dep.startswith("git+")]
for i, dep in enumerate(dependency_links):
    link = dep.split("git+")[1]
    name = dep.split("/")[-1]
    dependency_links[i] = f"{link}/tarball/master#egg={name}"

# Strip out git+ links from dependencies
dependencies = [dep for dep in dependencies if not dep.startswith("git+")]

# Setup
setup(
    name="pwncat",
    version="0.3.1",
    python_requires=">=3.8",
    description="A fancy reverse and bind shell handler",
    author="Caleb Stewart",
    url="https://gitlab.com/calebstewart/pwncat",
    packages=find_packages(),
    package_data={"pwncat": ["data/*"]},
    entry_points={
        "console_scripts": ["pwncat=pwncat.__main__:main", "pc=pwncat.__main__:main"]
    },
    data_files=[],
    install_requires=dependencies,
    dependency_links=dependency_links,
)
