# pwncat

pwncat is a raw bind and reverse shell handler. It streamlines common red team 
operations and all staging code is from your own attacker machine, not the target.

After receiving a connection, **pwncat** will setup some
common configurations when working with remote shells.

- Unset the `HISTFILE` environment variable to disable command history
- Normalize shell prompt
- Locate useful binaries (using `which`)
- Attempt to spawn a pseudoterminal (pty) for a full interactive session

`pwncat` knows how to spawn pty's with a few different methods and will
cross-reference the methods with the executables previously enumerated. After
spawning a pty, it will setup the controlling terminal in raw mode, so you can
interact in a similar fashion to `ssh`. 

`pwncat` will also synchronize the remote pty settings (such as rows, columns,
`TERM` environment variable) with your local settings to ensure the shell
behaves correctly.

John Hammond and I presented `pwncat` at GRIMMCon. Our presentation, which
covers the usage as well as some of the backend API can be found on YouTube
[here](https://www.youtube.com/watch?v=CISzI9klRkw).

pwncat [documentation] is being built out on Read the Docs. Head there for
the latest usage and development documentation!

## Install

`pwncat` only depends on a working Python development environment. In order
to install some of the packages required with `pip`, you will likely need
your distribution's "Python Development" package. On Debian based systems,
this is `python-dev`. For Arch, the development files are shipped with the
main Python repository. For Enterprise Linux, the package is named 
`python-devel`.

`pwncat` is configured as a standard python package with `distutils`. You
can install `pwncat` directly from GitHub with:

```shell script
pip install git+https://github.com/calebstewart/pwncat.git
```

Or, you can install after cloning the repository with:

```shell script
python setup.py install
```

`pwncat` depends on a custom fork of both `prompt_toolkit` and `paramiko`. 
The forks of these repositories simply added some small features which
weren't accessible in published releases. Pull requests have been submitted
upstream, but until they are (hopefully) merged, `pwncat` will continue to
explicitly reference these forks. As a result, it is recommended to run
`pwncat` from within a virtual environment in order to not pollute your
system environment with the custom packages. To setup a virtual environment
and install `pwncat`, you can use:

```shell script
python3 -m venv pwncat-env
source pwncat-env/bin/activate
python setup.py install
```

If you would like to develop custom privilege escalation or persistence
modules, we recommend you use the `develop` target vice the `install` target
for `setup.py`. This allows changes to the local repository to immediately
be observed with your installed package.

## Docker Image

The recommended installation method is a Python virtual environment. This
provides the easiest day-to-day usage of `pwncat`. However, there has been
interest in using `pwncat` from a docker image, so I have provided a
Dockerfile which provides a working `pwncat` installation. To build the image
use:

``` shell
docker build -t pwncat .
```

This will build the `pwncat` docker image with the tag "pwncat". The working
directory within the container is `/work`. The entrypoint for the container
is the `pwncat` binary. It can be used like so:

``` shell
# Connect to a bind shell at 10.0.0.1:4444
docker run -v "/some/directory":/work -t pwncat -C pwncatrc -c -H 10.0.0.1 -p 4444
```

In this example, only the files in `/some/directory` are exposed to the container.
Obviously, for upload/download, the container will only be able to see the files
exposed through any mounted directories.

## Features and Functionality

`pwncat` provides two main features. At it's core, it's goal is to automatically
setup a remote PseudoTerminal (pty) which allows interaction with the remote 
host much like a full SSH session. When operating in a pty, you can use common
features of your remote shell such as history, line editing, and graphical
terminal applications.

The other half of `pwncat` is a framework which utilizes your remote shell to
perform automated enumeration, persistence and privilege escalation tasks. The
local `pwncat` prompt provides a number of useful features for standard
penetration tests including:

* File upload and download
* Automated privilege escalation enumeration
* Automated privielge escalation execution
* Automated persistence installation/removal
* Automated tracking of modified/created files
    * `pwncat` also offers the ability to revert these remote "tampers" automatically

The underlying framework for interacting with the remote host aims to abstract
away the underlying shell and connection method as much as possible, allowing
commands and plugins to interact seamlessly with the remote host.

You can learn more about interacting with `pwncat` and about the underlying framework
in the [documentation]. If you have an idea for a
new privilege escalation method or persistence method, please take a look at the
API documentation specifically. Pull requests are welcome!

## Planned Features

**pwncat** would like to be come a red team swiss army knife. Hopefully soon,
more features will be added.

* More privilege escalation methods (sudo -u#-1 CVE, LXD containers, etc.)
* Persistence methods (bind shell, cronjobs, SSH access, PAM abuse, etc.)
* Aggression methods (spam randomness to terminals, flush firewall, etc.)
* Meme methods (terminal-parrot, cowsay, wall, etc.)
* Network methods (port forward, internet access through host, etc.)

[documentation]: https://pwncat.readthedocs.io/en/latest

## Known Issues

Because `pwncat` is trying to abstractly interact with any shell with minimal remote system 
dependencies, there are some edge cases we have found. Where we find them, we do
everything we can to account for them and hide them from the user. However, some have
slipped through the cracks and been observed in the wild. When this happens, `pwncat`
will do whatever it can to preserve your terminal, but you may be greeted with some 
peculiar output or command failures. 

### Dash Support

The Debian shell `dash` aims to be a very minimalistic shell. It's focus is not on user
interface, but on running scripts quickly and correctly. As a result, some of the features
we expect from an interactive shell simply don't work in `dash`. `pwncat` tries not to
depend on a specific shell environment, so if you start your reverse or bind shell with
`/bin/sh` or `/bin/dash`, then you may get a weird prompt. `dash` does not obey the
terminal escape sequences which `pwncat` adds, so you may get a very long terminal like this:

```shell script
\[\033[01;31m\](remote)\[\033[00m\] \[\033[01;33m\]\u@\h\[\033[00m\]:\[\033[01;36m\]\w\[\033[00m\]$
```

Currently, the only workaround is to use the `prompt` command at the local `pwncat` prompt.
The command allows you to modify the prompt which `pwncat` will automatically set whenever
resetting the remote terminal. Two options are provided: "basic" and "fancy". The "fancy"
prompt is the default which causes the above output in Dash. To switch to the basic prompt
you can use the following command at the `pwncat` prompt:

```shell script
prompt --basic
```

While this is inconvenient, it does not affect the behaviour of `pwncat`. All `pwncat`
features will continue to function properly no matter what your prompt looks like.

### BSD Support

While BSD is a Unix-based kernel, in practice it's userland tools are noticeably 
different from their Linux counterparts. Due to this, many of the automated
features of `pwncat` will not work or outright fail when running against a BSD
based target. I have tried to catch all errors or edge cases, however there are
likely some hiccups which haven't been fully tested against BSD. In any case,
the stabilized shell should function within a BSD environment, but I don't
provide any guarantees.

If I find some time later down the road, I may try to stabilize `pwncat` on BSD,
but for now my focus is on Linux-based distributions. If you'd like to
contribute to making `pwncat` behave better on BSD, you are more then welcome to
reach out or just fork the repo. As always, pull requests are welcome!
