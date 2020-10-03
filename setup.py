#!/usr/bin/env python

from setuptools import find_packages
from setuptools import setup
from setuptools.command.install import install
import shutil, os, stat
import binascii

dependencies = [
    "base64io==1.0.3",
    "bcrypt==3.1.7",
    "certifi==2020.6.20",
    "cffi==1.14.0",
    "chardet==3.0.4",
    "colorama==0.4.3",
    "commentjson==0.8.3",
    "commonmark==0.9.1",
    "cryptography==2.9.2",
    "DataProperty==0.49.1",
    "idna==2.10",
    "lark-parser==0.7.8",
    "mbstrdecoder==1.0.0",
    "msgfy==0.1.0",
    "netifaces==0.10.9",
    "paramiko==2.7.1",
    "pathvalidate==2.3.0",
    "pprintpp==0.4.0",
    "prompt-toolkit==3.0.5",
    "pycparser==2.20",
    "pycryptodome==3.9.8",
    "Pygments==2.6.1",
    "PyNaCl==1.4.0",
    "pytablewriter==0.54.0",
    "python-dateutil==2.8.1",
    "pytz==2020.1",
    "requests==2.24.0",
    "rich",
    "six==1.15.0",
    "SQLAlchemy==1.3.18",
    "tabledata==1.1.2",
    "tcolorpy==0.0.5",
    "typepy==1.1.1",
    "typing-extensions==3.7.4.2",
    "urllib3==1.25.9",
    "wcwidth==0.1.9",
    "python-rapidjson==0.9.1",
]

dependency_links = [
    "https://github.com/calebstewart/paramiko/tarball/master#egg=paramiko",
    "https://github.com/JohnHammond/base64io-python/tarball/master#egg=base64io",
]

# Setup
setup(
    name="pwncat",
    version="0.3.1",
    python_requires='>=3.8',
    description="A fancy reverse and bind shell handler",
    author="Caleb Stewart",
    url="https://gitlab.com/calebstewart/pwncat",
    packages=find_packages(),
    package_data={"pwncat": ["data/*"]},
    entry_points={"console_scripts": ["pwncat=pwncat.__main__:main", "pc=pwncat.__main__:main"]},
    data_files=[],
    install_requires=dependencies,
    dependency_links=dependency_links,
)
