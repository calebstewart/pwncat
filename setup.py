#!/usr/bin/env python

from setuptools import setup, find_packages

dependencies = [
    "netifaces",
    "packaging",
    "prompt-toolkit",
    "pycryptodome",
    "requests",
    "rich",
    "python-rapidjson",
    "ZODB",
    "zodburi",
    "Jinja2",
    "paramiko",
]
dependency_links = []

# Setup
setup(
    name="pwncat",
    version="0.4.2",
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
