#!/usr/bin/env python3
import textwrap

import pwncat
from pwncat.commands.base import CommandDefinition


class Command(CommandDefinition):

    PROG = "service"
    ARGS = {}

    def run(self, args):
        with pwncat.victim.open("/tmp/pwncat", "w") as filp:
            filp.write(
                textwrap.dedent(
                    """
            #!/usr/bin/env bash
            
            while [ 1 ]; do
                echo "Running"
                sleep 3
            done
            
            """
                ).lstrip()
            )
        pwncat.victim.env(["chmod", "777", "/tmp/pwncat"])

        pwncat.victim.create_service(
            "pwncat", "test pwncat service", "/tmp/pwncat", "root", False
        ).start()
