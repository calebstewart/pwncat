# pwncat - fancy reverse and bind shell handler

This is a little tool to make interacting with raw reverse and bind shells a
little nicer. `pwncat` can either connect to a remote bind shell or listen for
an incoming reverse shell. After receiving a connection, it will setup some
common configurations when working with remote shells. For example:

- Unset the `HIST_FILE` macro to disable bash history
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

## Command and Control Features

`pwncat` has a few useful features baked in for interacting with a remote shell.
You can access a local command interpreter at any time by getting to a blank
line and pressing the sequence `~C` (that's ``Shift+` `` then `Shift+c`). This new
prompt provides some basic interaction between your local host and the remote
host.

When at this prompt, you can return to your shell at any time with `C-d` or the
"back" command. To get a list of available commands, you can use `help`. At the
time of writing the following commands are supported:

- `sync`: synchronize rows/columns and TERM environment.
- `set`: set local variables (such as `lhost`).
- `upload`: upload files to the remote host


## Uploading Files

The `upload` command in the local shell allows you to upload files quickly and
easily. `pwncat` can use a variety of methods to transfer the files, and will
use the best one given the executables it was able to find. If none of the
required executables were found, `pwncat` will transfer the file in chunks of
base64, and decode them on the other end. This is slower, but will work in a
pinch.

The usage is simple, but you must set the `lhost` variable first with te `set`
command so that `pwncat` knows how to instruct the remote host to connect to us.

```
localhost$ set lhost "8.8.8.8"
```

Once that is set up, you can upload files but specifying a local file name:

```
localhost$ upload /opt/tools/linpeas.sh
```

By default, the file will be written to the current working directory of your
remote shell. You can use the `--output/-o` option to direct the output to a
directory/file of your choosing. You can also select a specific method, if you
would like, however that shouldn't be necessary. The default method is to
automatically select the best available. `pwncat` even gives you a nice progress
bar while it uploads!

## More to come!

I wrote this in the last few days, and there's bound to be bugs or edge-cases.
Further, I want to build out the local prompt commands more. Obviously, a
download option would be ideal, but since the interaction with the remote
terminal is scriptable, the sky is the limit.

Another feature that I plan to implement soon is tab completions for the local
prompt (remote tab completions work already thanks to the pty ;). I'll be
working on that ASAP.
