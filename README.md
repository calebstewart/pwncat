# pwncat

[![asciicast](https://asciinema.org/a/417930.svg)](https://asciinema.org/a/417930)

pwncat is a post-exploitation platform ~~for Linux targets~~. It started out as a
wrapper around basic bind and reverse shells and has grown from there. It
streamlines common red team operations while staging code from your attacker
machine, not the target.

pwncat used to only support Linux, but there has been a lot of work recently
to support multiple platforms. Currently, there is alpha support for Windows
targets. Please see the latest [documentation] for details on how to use
pwncat with a Windows target.

pwncat intercepts the raw communication with a remote shell and allows the
user to perform automated actions on the remote host including enumeration,
implant installation and even privilege escalation.

After receiving a connection, pwncat will setup some common configurations
for working with remote shells.

- Disable history in the remote shell
- Normalize shell prompt
- Locate useful binaries (using `which`)
- Attempt to spawn a pseudoterminal (pty) for a full interactive session

`pwncat` knows how to spawn pty's with a few different methods and will
cross-reference the methods with the executables previously enumerated. After
spawning a pty, it will setup the controlling terminal in raw mode, so you can
interact in a similar fashion to `ssh`. 

`pwncat` will also synchronize the remote pty settings (such as rows, columns,
`TERM` environment variable) with your local settings to ensure the shell
behaves correctly with interactive applications such as `vim` or `nano`.

John Hammond and I presented `pwncat` at GRIMMCon. Our presentation, which
can be found on YouTube [here](https://www.youtube.com/watch?v=CISzI9klRkw).
This video demonstrates an early version of the API and interface. Please
refer to the documentation for up to date usage and API documentation!

pwncat [documentation] is being built out on Read the Docs. Head there for
the latest usage and development documentation!

**pwncat requires Python 3.9+.**

## Installation

pwncat is available on PyPI as `pwncat-cs`. It exposes an entrypoints named
`pwncat`, `pcat` and `pc`. It **does** conflict with the `pwncat` package,
so if you need both, we recommend using a virtual environment. pwncat also
exposes an importable module named `pwncat` with full access to the internals
and automation. You can install from PyPi like so:

``` shell
pip install pwncat-cs
```

pwncat uses [poetry](https://python-poetry.org) for dependency and build
management. For a development environment, install poetry as described on their
website, and then use it to manage your environment:

``` shell
# Clone the repo
git clone https://github.com/calebstewart/pwncat
cd pwncat
# Enter/create the pwncat specific virtual environment
poetry shell
# Install dependencies
poetry install
# Use pwncat
pwncat --help
# Use `exit` to leave the virtual environment
exit
```

## Windows Support

pwncat now supports windows starting at `v0.4.0a1`. The Windows platform
utilizes a .Net-based C2 library which is loaded automatically. Windows
targets should connect with either a `cmd.exe` or `powershell.exe` shell, and
pwncat will take care of the rest.

The libraries implementing the C2 are implemented at [pwncat-windows-c2].
The DLLs for the C2 will be automatically downloaded from the targeted release
for you. If you do not have internet connectivity on your target machine,
you can tell pwncat to prestage the DLLs using the `--download-plugins`
argument. If you are running a release version of pwncat, you can also download
a tarball of all built-in plugins from the releases page.

The plugins are stored by default in `~/.local/share/pwncat`, however this is
configurable with the `plugin_path` configuration. If you download the packaged
set of plugins from the releases page, you should extract it to the path pointed
to by `plugin_path`.

Aside from the main C2 DLLs, other plugins may also be available. Currently,
the only provided default plugins are the C2 and an implementation of [BadPotato].
pwncat can reflectively load .Net binaries to be used a plugins for the C2.
For more information on Windows C2 plugins, please see the [documentation].

## Modules

Recently, the architecture of the pwncat framework was redesigned to
encorporate a generic "module" structure. All functionality is now 
implemented as modules. This includes enumeration, persistence and
privilege escalation. Interacting with modules is similar to most other
post-exploitation platforms. You can utilize the familiar `run`, `search`
and `info` commands and enter module contexts with the `use` command.
Refer to the documentation for more information.

### Connecting to a Victim

The command line parameters for pwncat attempt to be flexible and accept 
a variety of common connection syntax. Specifically, it will try to accept
common netcat and ssh like syntax. The following are all valid:

```sh
# Connect to a bind shell
pwncat connect://10.10.10.10:4444
pwncat 10.10.10.10:4444
pwncat 10.10.10.10 4444
# Listen for reverse shell
pwncat bind://0.0.0.0:4444
pwncat 0.0.0.0:4444
pwncat :4444
pwncat -lp 4444
# Connect via ssh
pwncat ssh://user:password@10.10.10.10
pwncat user@10.10.10.10
pwncat user:password@10.10.10.10
pwncat -i id_rsa user@10.10.10.10
# SSH w/ non-standard port
pwncat -p 2222 user@10.10.10.10
pwncat user@10.10.10.10:2222
# Reconnect utilizing installed persistence
#   If reconnection failes and no protocol is specified,
#   SSH is used as a fallback.
pwncat reconnect://user@10.10.10.10
pwncat reconnect://user@c228fc49e515628a0c13bdc4759a12bf
pwncat user@10.10.10.10
pwncat c228fc49e515628a0c13bdc4759a12bf
pwncat 10.10.10.10
```

By default, pwncat **assumes the target platform is Linux**. In order to
connect to a Windows reverse or bind shell, you must pass the `--platform/-m`
argument:

``` shell
pwncat -m windows 10.10.10.10 4444
pwncat -m windows -lp 4444
```

For more information on the syntax and argument handling, see the 
help information with ``pwncat --help`` or visit the [documentation].

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
docker run -v "/some/directory":/work -t pwncat 10.0.0.1 4444
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
* Automated privilege escalation execution
* Automated persistence installation/removal
* Automated tracking of modified/created files
    * `pwncat` also offers the ability to revert these remote "tampers" automatically

The underlying framework for interacting with the remote host aims to abstract
away the underlying shell and connection method as much as possible, allowing
commands and plugins to interact seamlessly with the remote host.

You can learn more about interacting with `pwncat` and about the underlying framework
in the [documentation]. If you have an idea for a new privilege escalation method
or persistence method, please take a look at the API documentation specifically.
Pull requests are welcome!

## Planned Features

**pwncat** would like to be come a red team swiss army knife. Hopefully soon,
more features will be added.

* More privilege escalation methods (sudo -u#-1 CVE, LXD containers, etc.)
* Persistence methods (bind shell, cronjobs, SSH access, PAM abuse, etc.)
* Aggression methods (spam randomness to terminals, flush firewall, etc.)
* Meme methods (terminal-parrot, cowsay, wall, etc.)
* Network methods (port forward, internet access through host, etc.)

## Known Issues

Because `pwncat` is trying to abstractly interact with any shell with minimal remote system 
dependencies, there are some edge cases we have found. Where we find them, we do
everything we can to account for them and hide them from the user. However, some have
slipped through the cracks and been observed in the wild. When this happens, `pwncat`
will do whatever it can to preserve your terminal, but you may be greeted with some 
peculiar output or command failures. 

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

[documentation]: https://pwncat.readthedocs.io/en/latest
[pwncat-windows-c2]: https://github.com/calebstewart/pwncat-windows-c2
[BadPotato]: https://github.com/calebstewart/pwncat-badpotato
